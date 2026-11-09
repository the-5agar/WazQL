"""
query_engine.py
===============

A validated, recursive query DSL for Wazuh / OpenSearch alerts.

Pipeline
--------
    raw dict --(guard)--> pydantic models --(registry validation)--> typed tree
             --(recursive walk)--> OpenSearch body  /  in-memory match  /  field list

Example payload
---------------
{
  "index": "wazuh-alerts-*",
  "where": {
    "and": [
      {"field": "rule.level", "operator": "gte", "value": 10},
      {"or": [
        {"field": "agent.id", "operator": "eq", "value": "001"},
        {"field": "agent.id", "operator": "eq", "value": "002"}
      ]}
    ]
  },
  "time_range": {"field": "@timestamp", "from": "now-24h", "to": "now"},
  "sort": {"field": "@timestamp", "order": "desc"},
  "pagination": {"limit": 100, "offset": 0}
}

Requires: pydantic>=2.6, Python>=3.11
"""

from __future__ import annotations

import fnmatch
import operator as pyop
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal, Union

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    model_validator,
)

# --------------------------------------------------------------------------- #
# Limits (protect against hostile / accidental huge payloads)
# --------------------------------------------------------------------------- #
MAX_DEPTH = 8              # max nesting of and/or/not groups
MAX_NODES = 50             # max total conditions + groups in one where-tree
MAX_LIST_VALUES = 100      # max items for in / not_in
MAX_RESULT_WINDOW = 10_000  # OpenSearch default index.max_result_window


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Operator(StrEnum):
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    WILDCARD = "wildcard"


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"


LIST_OPS = frozenset({Operator.IN, Operator.NOT_IN})
RANGE_OPS = frozenset({Operator.GT, Operator.GTE, Operator.LT, Operator.LTE})
FLAG_OPS = frozenset({Operator.EXISTS})


# --------------------------------------------------------------------------- #
# Field registry: stores allowed operators / values per field
# --------------------------------------------------------------------------- #
class FieldSpec(BaseModel):
    """Declarative description of one queryable field."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str
    value_type: Any                                   # int, str, ...
    operators: frozenset[Operator]
    allowed_values: tuple[Any, ...] | None = None     # closed set, e.g. levels 0-15
    sortable: bool = False

    def scalar_type(self) -> Any:
        """Type of ONE value. A closed set becomes a Literal."""
        if self.allowed_values is not None:
            return Literal[self.allowed_values]       # tuple is unpacked by Literal
        return self.value_type


class Registry:
    """Holds field specs and caches one TypeAdapter per (field, operator)."""

    def __init__(self, index: str, specs: list[FieldSpec]):
        self.index = index
        self.specs: dict[str, FieldSpec] = {s.name: s for s in specs}
        self._adapters: dict[tuple[str, Operator], TypeAdapter] = {}

    def adapter(self, field: str, op: Operator) -> TypeAdapter:
        key = (field, op)
        if key not in self._adapters:
            t = self.specs[field].scalar_type()
            if op in LIST_OPS:
                t = Annotated[list[t], Field(min_length=1, max_length=MAX_LIST_VALUES)]
            elif op in FLAG_OPS:
                t = bool
            elif op is Operator.WILDCARD:
                t = str
            self._adapters[key] = TypeAdapter(t)
        return self._adapters[key]

    def meta(self) -> dict[str, Any]:
        """JSON-serialisable description, e.g. for a /search/meta endpoint."""
        return {
            "index": self.index,
            "fields": [
                {
                    "name": s.name,
                    "operators": sorted(o.value for o in s.operators),
                    "allowed_values": list(s.allowed_values) if s.allowed_values else None,
                    "sortable": s.sortable,
                    "json_schema": TypeAdapter(s.scalar_type()).json_schema(),
                }
                for s in self.specs.values()
            ],
        }


def build_wazuh_registry() -> Registry:
    """Example registry. Adjust to your own mapping."""
    O = Operator
    return Registry(
        index="wazuh-alerts-*",
        specs=[
            FieldSpec(
                name="rule.level",
                value_type=int,
                operators=frozenset({O.EQ, O.NE, O.GT, O.GTE, O.LT, O.LTE, O.IN, O.NOT_IN}),
                allowed_values=tuple(range(0, 16)),            # Wazuh levels: 0-15
                sortable=True,
            ),
            FieldSpec(
                name="rule.id",
                value_type=str,
                operators=frozenset({O.EQ, O.NE, O.IN, O.NOT_IN}),
            ),
            FieldSpec(
                name="rule.groups",
                value_type=str,
                operators=frozenset({O.EQ, O.IN, O.NOT_IN}),
            ),
            FieldSpec(
                name="agent.id",
                value_type=str,
                operators=frozenset({O.EQ, O.NE, O.IN, O.NOT_IN}),
                sortable=True,
            ),
            FieldSpec(
                name="agent.name",
                value_type=str,
                operators=frozenset({O.EQ, O.NE, O.IN, O.NOT_IN, O.WILDCARD, O.EXISTS}),
                sortable=True,
            ),
            FieldSpec(
                name="data.srcip",
                value_type=str,
                operators=frozenset({O.EQ, O.NE, O.IN, O.NOT_IN, O.EXISTS}),
            ),
            FieldSpec(
                name="@timestamp",
                value_type=str,
                operators=frozenset({O.GT, O.GTE, O.LT, O.LTE}),
                sortable=True,
            ),
        ],
    )


def _registry_from(info: ValidationInfo) -> Registry | None:
    return (info.context or {}).get("registry")


# --------------------------------------------------------------------------- #
# Tree node models (recursive)
# --------------------------------------------------------------------------- #
class Condition(BaseModel):
    """Leaf: field <operator> value."""

    model_config = ConfigDict(extra="forbid")

    field: str
    operator: Operator
    value: Any = None

    @model_validator(mode="after")
    def _validate_against_registry(self, info: ValidationInfo) -> Condition:
        registry = _registry_from(info)
        if registry is None:
            return self                      # structural validation only

        spec = registry.specs.get(self.field)
        if spec is None:
            raise ValueError(
                f"Unknown field '{self.field}'. Allowed: {sorted(registry.specs)}"
            )
        if self.operator not in spec.operators:
            raise ValueError(
                f"Operator '{self.operator.value}' is not allowed for '{self.field}'. "
                f"Allowed: {sorted(o.value for o in spec.operators)}"
            )

        value = self.value
        if self.operator in FLAG_OPS and value is None:
            value = True                     # {"operator": "exists"} means "must exist"

        try:
            self.value = registry.adapter(self.field, self.operator).validate_python(value)
        except ValidationError as exc:
            detail = "; ".join(e["msg"] for e in exc.errors(include_url=False))
            raise ValueError(
                f"Invalid value {value!r} for '{self.field}' "
                f"with operator '{self.operator.value}': {detail}"
            ) from None
        return self


class And(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    and_: list[Node] = Field(alias="and", min_length=1)


class Or(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    or_: list[Node] = Field(alias="or", min_length=1)


class Not(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    not_: Node = Field(alias="not")


def _node_tag(v: Any) -> str | None:
    """Pick the union member by looking at the keys: clear errors, no guessing."""
    if isinstance(v, dict):
        if "and" in v:
            return "and"
        if "or" in v:
            return "or"
        if "not" in v:
            return "not"
        return "condition"
    return {Condition: "condition", And: "and", Or: "or", Not: "not"}.get(type(v))


Node = Annotated[
    Union[
        Annotated[Condition, Tag("condition")],
        Annotated[And, Tag("and")],
        Annotated[Or, Tag("or")],
        Annotated[Not, Tag("not")],
    ],
    Discriminator(_node_tag),
]

# Resolve the forward reference to "Node" in the recursive models.
And.model_rebuild()
Or.model_rebuild()
Not.model_rebuild()


# --------------------------------------------------------------------------- #
# Time range
# --------------------------------------------------------------------------- #
_DATE_MATH = re.compile(r"^now(?:[+-]\d+[smhdwMy])*(?:/[smhdwMy])?$")


def _parse_iso(v: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _check_time_expr(v: str) -> str:
    if _DATE_MATH.match(v) or _parse_iso(v) is not None:
        return v
    raise ValueError(
        f"Invalid time expression {v!r}. Use 'now', 'now-24h', 'now-7d/d' or an ISO date."
    )


TimeExpr = Annotated[str, AfterValidator(_check_time_expr)]


class TimeRange(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    field: str = "@timestamp"
    from_: TimeExpr = Field(alias="from")        # "from" is a Python keyword
    to: TimeExpr = "now"

    @model_validator(mode="after")
    def _ordered(self) -> TimeRange:
        a, b = _parse_iso(self.from_), _parse_iso(self.to)
        if a and b and a > b:
            raise ValueError("time_range.from must be earlier than time_range.to")
        return self


# --------------------------------------------------------------------------- #
# Sort / pagination
# --------------------------------------------------------------------------- #
class Sort(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    order: SortOrder = SortOrder.DESC


class Pagination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _window(self) -> Pagination:
        if self.offset + self.limit > MAX_RESULT_WINDOW:
            raise ValueError(
                f"offset + limit must be <= {MAX_RESULT_WINDOW}; use search_after for deeper paging"
            )
        return self


# --------------------------------------------------------------------------- #
# Top-level request
# --------------------------------------------------------------------------- #
class SearchQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: str | None = Field(default=None, pattern=r"^[a-z0-9_\-\*\.]+$")
    where: Node | None = None
    time_range: TimeRange | None = None
    sort: Sort | None = None
    pagination: Pagination = Field(default_factory=Pagination)

    @model_validator(mode="after")
    def _validate_against_registry(self, info: ValidationInfo) -> SearchQuery:
        registry = _registry_from(info)
        if registry is None:
            return self

        if self.index is not None and self.index != registry.index:
            raise ValueError(f"Index '{self.index}' is not permitted")

        if self.sort:
            spec = registry.specs.get(self.sort.field)
            if spec is None or not spec.sortable:
                sortable = sorted(n for n, s in registry.specs.items() if s.sortable)
                raise ValueError(f"Cannot sort by '{self.sort.field}'. Sortable: {sortable}")

        if self.time_range and self.time_range.field not in registry.specs:
            raise ValueError(f"Unknown time field '{self.time_range.field}'")

        if self.where is not None and count_nodes(self.where) > MAX_NODES:
            raise ValueError(f"Query has more than {MAX_NODES} nodes")
        return self


# --------------------------------------------------------------------------- #
# Guard: run BEFORE pydantic parses untrusted input
# --------------------------------------------------------------------------- #
class QueryTooComplex(ValueError):
    pass


def check_raw_where(node: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    """Cheap recursive pre-check on the raw dict. Stops as soon as limits break,
    so a 10,000-level payload never reaches pydantic or Python's recursion limit."""
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if counter[0] > MAX_NODES:
        raise QueryTooComplex(f"Query has more than {MAX_NODES} nodes")
    if depth > MAX_DEPTH:
        raise QueryTooComplex(f"Query nested deeper than {MAX_DEPTH} levels")
    if not isinstance(node, dict):
        return
    for key in ("and", "or"):
        children = node.get(key)
        if isinstance(children, list):
            for child in children:
                check_raw_where(child, depth + 1, counter)
    if "not" in node:
        check_raw_where(node["not"], depth + 1, counter)


def parse_query(payload: dict[str, Any], registry: Registry | None = None) -> SearchQuery:
    """The one entry point: guard, then validate (optionally against a registry)."""
    if isinstance(payload, dict) and "where" in payload:
        check_raw_where(payload["where"])
    return SearchQuery.model_validate(
        payload, context={"registry": registry} if registry else None
    )


# --------------------------------------------------------------------------- #
# Recursive walkers over the typed tree
# --------------------------------------------------------------------------- #
def children_of(node: And | Or) -> list[Node]:
    return node.and_ if isinstance(node, And) else node.or_


def count_nodes(node: Node) -> int:
    """Total nodes (groups + leaves)."""
    if isinstance(node, Condition):
        return 1
    if isinstance(node, Not):
        return 1 + count_nodes(node.not_)
    return 1 + sum(count_nodes(c) for c in children_of(node))


def tree_depth(node: Node) -> int:
    if isinstance(node, Condition):
        return 0
    if isinstance(node, Not):
        return 1 + tree_depth(node.not_)
    return 1 + max(tree_depth(c) for c in children_of(node))


def collect_fields(node: Node) -> set[str]:
    """Every field referenced anywhere in the tree (handy for permission checks)."""
    if isinstance(node, Condition):
        return {node.field}
    if isinstance(node, Not):
        return collect_fields(node.not_)
    return set().union(*(collect_fields(c) for c in children_of(node)))


# ---- translation to OpenSearch ------------------------------------------------ #
def leaf_to_opensearch(c: Condition) -> dict[str, Any]:
    match c.operator:
        case Operator.EQ:
            return {"term": {c.field: c.value}}
        case Operator.NE:
            return {"bool": {"must_not": [{"term": {c.field: c.value}}]}}
        case Operator.IN:
            return {"terms": {c.field: c.value}}
        case Operator.NOT_IN:
            return {"bool": {"must_not": [{"terms": {c.field: c.value}}]}}
        case Operator.WILDCARD:
            return {"wildcard": {c.field: {"value": c.value}}}
        case Operator.EXISTS:
            exists = {"exists": {"field": c.field}}
            return exists if c.value else {"bool": {"must_not": [exists]}}
        case Operator.GT | Operator.GTE | Operator.LT | Operator.LTE:
            return {"range": {c.field: {c.operator.value: c.value}}}
    raise ValueError(f"Unsupported operator {c.operator}")      # pragma: no cover


def node_to_opensearch(node: Node, depth: int = 0) -> dict[str, Any]:
    """Recursive: leaf -> base case; groups -> translate children, then combine."""
    if depth > MAX_DEPTH:
        raise QueryTooComplex(f"Query nested deeper than {MAX_DEPTH} levels")

    # base case
    if isinstance(node, Condition):
        return leaf_to_opensearch(node)

    # recursive cases
    if isinstance(node, And):
        return {"bool": {"filter": [node_to_opensearch(c, depth + 1) for c in node.and_]}}

    if isinstance(node, Or):
        return {
            "bool": {
                "should": [node_to_opensearch(c, depth + 1) for c in node.or_],
                "minimum_should_match": 1,
            }
        }

    if isinstance(node, Not):
        return {"bool": {"must_not": [node_to_opensearch(node.not_, depth + 1)]}}

    raise TypeError(f"Unknown node type: {type(node).__name__}")   # pragma: no cover


def to_opensearch(q: SearchQuery) -> dict[str, Any]:
    """Full request body for POST /<index>/_search."""
    filters: list[dict[str, Any]] = []

    if q.where is not None:
        filters.append(node_to_opensearch(q.where))

    if q.time_range is not None:
        t = q.time_range
        filters.append({"range": {t.field: {"gte": t.from_, "lte": t.to}}})

    body: dict[str, Any] = {
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        "from": q.pagination.offset,
        "size": q.pagination.limit,
    }
    if q.sort is not None:
        body["sort"] = [{q.sort.field: {"order": q.sort.order.value}}]
    return body


# ---- in-memory evaluation (tests, previews, client-side filtering) ------------- #
_CMP = {
    Operator.GT: pyop.gt,
    Operator.GTE: pyop.ge,
    Operator.LT: pyop.lt,
    Operator.LTE: pyop.le,
}


def get_path(doc: dict[str, Any], path: str) -> Any:
    """Read 'rule.level' from {'rule': {'level': 5}} or from a flat {'rule.level': 5}."""
    if path in doc:
        return doc[path]
    cur: Any = doc
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _leaf_matches(c: Condition, doc: dict[str, Any]) -> bool:
    actual = get_path(doc, c.field)

    if c.operator is Operator.EXISTS:
        return (actual is not None) == bool(c.value)

    values = actual if isinstance(actual, list) else [actual]   # multi-valued fields
    values = [v for v in values if v is not None]

    try:
        match c.operator:
            case Operator.EQ:
                return any(v == c.value for v in values)
            case Operator.NE:
                return not any(v == c.value for v in values)
            case Operator.IN:
                return any(v in c.value for v in values)
            case Operator.NOT_IN:
                return not any(v in c.value for v in values)
            case Operator.WILDCARD:
                return any(fnmatch.fnmatchcase(str(v), c.value) for v in values)
            case _:
                return any(_CMP[c.operator](v, c.value) for v in values)
    except TypeError:                     # e.g. comparing str with int
        return False


def matches(node: Node, doc: dict[str, Any]) -> bool:
    if isinstance(node, Condition):
        return _leaf_matches(node, doc)
    if isinstance(node, And):
        return all(matches(c, doc) for c in node.and_)        # short-circuits
    if isinstance(node, Or):
        return any(matches(c, doc) for c in node.or_)         # short-circuits
    if isinstance(node, Not):
        return not matches(node.not_, doc)
    raise TypeError(f"Unknown node type: {type(node).__name__}")   # pragma: no cover


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import json

    registry = build_wazuh_registry()

    payload = {
        "index": "wazuh-alerts-*",
        "where": {
            "and": [
                {"field": "rule.level", "operator": "gte", "value": 10},
                {
                    "or": [
                        {"field": "agent.id", "operator": "eq", "value": "001"},
                        {"field": "agent.id", "operator": "eq", "value": "002"},
                    ]
                },
            ]
        },
        "time_range": {"field": "@timestamp", "from": "now-24h", "to": "now"},
        "sort": {"field": "@timestamp", "order": "desc"},
        "pagination": {"limit": 100, "offset": 0},
    }

    q = parse_query(payload, registry)
    print("== OpenSearch body ==")
    print(json.dumps(to_opensearch(q), indent=2))

    print("\n== Fields used ==", sorted(collect_fields(q.where)))
    print("== Nodes / depth ==", count_nodes(q.where), "/", tree_depth(q.where))

    print("\n== In-memory matching ==")
    for doc in (
        {"rule": {"level": 12}, "agent": {"id": "002"}},
        {"rule": {"level": 12}, "agent": {"id": "003"}},
        {"rule": {"level": 5}, "agent": {"id": "001"}},
    ):
        print(doc, "->", matches(q.where, doc))

    print("\n== Round trip (aliases preserved) ==")
    print(json.dumps(q.model_dump(by_alias=True, mode="json", exclude_none=True)["where"], indent=1)[:200], "...")

    print("\n== Validation errors ==")
    bad_payloads = {
        "level out of range": {"where": {"field": "rule.level", "operator": "gte", "value": 99}},
        "operator not allowed": {"where": {"field": "rule.level", "operator": "wildcard", "value": "1*"}},
        "unknown field": {"where": {"field": "nope", "operator": "eq", "value": 1}},
        "scalar given to list op": {"where": {"field": "agent.id", "operator": "in", "value": "001"}},
        "bad sort field": {"sort": {"field": "rule.groups", "order": "asc"}},
        "mixed and/or keys": {"where": {"and": [], "or": []}},
    }
    for name, bad in bad_payloads.items():
        try:
            parse_query(bad, registry)
        except ValidationError as e:
            err = e.errors(include_url=False)[0]
            print(f"- {name}: {err['msg']}")
