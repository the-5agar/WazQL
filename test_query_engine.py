import pytest
from pydantic import ValidationError

from query_engine import (
    MAX_DEPTH,
    And,
    Condition,
    Not,
    Or,
    QueryTooComplex,
    build_wazuh_registry,
    collect_fields,
    count_nodes,
    matches,
    parse_query,
    to_opensearch,
    tree_depth,
)

REG = build_wazuh_registry()

PAYLOAD = {
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


def nested(depth: int) -> dict:
    node: dict = {"field": "rule.level", "operator": "gte", "value": 1}
    for _ in range(depth):
        node = {"and": [node]}
    return node


# ---------------------------------------------------------------- parsing ---
def test_tree_shape():
    q = parse_query(PAYLOAD, REG)
    assert isinstance(q.where, And)
    assert isinstance(q.where.and_[0], Condition)
    assert isinstance(q.where.and_[1], Or)
    assert count_nodes(q.where) == 5
    assert tree_depth(q.where) == 2
    assert collect_fields(q.where) == {"rule.level", "agent.id"}


def test_structural_validation_without_registry():
    q = parse_query({"where": {"field": "anything", "operator": "eq", "value": 1}})
    assert isinstance(q.where, Condition)


def test_not_node():
    q = parse_query({"where": {"not": {"field": "rule.level", "operator": "lt", "value": 5}}}, REG)
    assert isinstance(q.where, Not)
    assert matches(q.where, {"rule": {"level": 7}})
    assert not matches(q.where, {"rule": {"level": 3}})


def test_alias_round_trip():
    q = parse_query(PAYLOAD, REG)
    dumped = q.model_dump(by_alias=True, mode="json", exclude_none=True)
    assert "and" in dumped["where"]
    assert dumped["time_range"]["from"] == "now-24h"


# ------------------------------------------------------------- validation ---
@pytest.mark.parametrize(
    "where, fragment",
    [
        ({"field": "rule.level", "operator": "gte", "value": 99}, "Input should be"),
        ({"field": "rule.level", "operator": "wildcard", "value": "1*"}, "not allowed"),
        ({"field": "nope", "operator": "eq", "value": 1}, "Unknown field"),
        ({"field": "agent.id", "operator": "in", "value": "001"}, "valid list"),
        ({"field": "agent.id", "operator": "in", "value": []}, "at least 1"),
        ({"field": "agent.id", "operator": "eq", "value": 1}, "valid string"),
        ({"field": "agent.id", "operator": "bogus", "value": "1"}, "Input should be"),
        ({"field": "agent.id", "operator": "eq", "value": "1", "extra": 1}, "Extra inputs"),
    ],
)
def test_invalid_conditions(where, fragment):
    with pytest.raises(ValidationError) as exc:
        parse_query({"where": where}, REG)
    assert fragment in str(exc.value)


def test_invalid_condition_nested_deep_inside_tree():
    bad = {"and": [{"or": [{"field": "rule.level", "operator": "eq", "value": 100}]}]}
    with pytest.raises(ValidationError) as exc:
        parse_query({"where": bad}, REG)
    assert "where" in str(exc.value)


def test_group_with_unknown_key_rejected():
    with pytest.raises(ValidationError):
        parse_query({"where": {"and": [], "xor": []}}, REG)


@pytest.mark.parametrize(
    "extra",
    [
        {"index": "other-index-*"},
        {"sort": {"field": "rule.groups", "order": "asc"}},
        {"time_range": {"field": "nope", "from": "now-1h"}},
        {"time_range": {"from": "yesterday-ish"}},
        {"time_range": {"from": "2026-02-01", "to": "2026-01-01"}},
        {"pagination": {"limit": 5000}},
        {"pagination": {"limit": 1000, "offset": 9500}},
    ],
)
def test_invalid_top_level(extra):
    with pytest.raises(ValidationError):
        parse_query(extra, REG)


def test_exists_defaults_to_true():
    q = parse_query({"where": {"field": "agent.name", "operator": "exists"}}, REG)
    assert q.where.value is True


# ------------------------------------------------------------ guard rails ---
def test_depth_limit_enforced_before_parsing():
    parse_query({"where": nested(MAX_DEPTH)}, REG)            # at the limit: ok
    with pytest.raises(QueryTooComplex):
        parse_query({"where": nested(MAX_DEPTH + 1)}, REG)


def test_absurd_depth_does_not_blow_the_stack():
    with pytest.raises(QueryTooComplex):
        parse_query({"where": nested(5000)}, REG)


def test_node_limit():
    wide = {"or": [{"field": "rule.level", "operator": "eq", "value": 1}] * 500}
    with pytest.raises(QueryTooComplex):
        parse_query({"where": wide}, REG)


# ------------------------------------------------------------ translation ---
def test_opensearch_translation():
    body = to_opensearch(parse_query(PAYLOAD, REG))
    assert body["from"] == 0 and body["size"] == 100
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]

    where_q, time_q = body["query"]["bool"]["filter"]
    assert where_q == {
        "bool": {
            "filter": [
                {"range": {"rule.level": {"gte": 10}}},
                {
                    "bool": {
                        "should": [
                            {"term": {"agent.id": "001"}},
                            {"term": {"agent.id": "002"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    }
    assert time_q == {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}


def test_no_filters_means_match_all():
    assert to_opensearch(parse_query({}, REG))["query"] == {"match_all": {}}


@pytest.mark.parametrize(
    "cond, expected",
    [
        ({"field": "agent.id", "operator": "ne", "value": "1"},
         {"bool": {"must_not": [{"term": {"agent.id": "1"}}]}}),
        ({"field": "agent.id", "operator": "in", "value": ["1", "2"]},
         {"terms": {"agent.id": ["1", "2"]}}),
        ({"field": "agent.id", "operator": "not_in", "value": ["1"]},
         {"bool": {"must_not": [{"terms": {"agent.id": ["1"]}}]}}),
        ({"field": "agent.name", "operator": "wildcard", "value": "db-*"},
         {"wildcard": {"agent.name": {"value": "db-*"}}}),
        ({"field": "agent.name", "operator": "exists", "value": False},
         {"bool": {"must_not": [{"exists": {"field": "agent.name"}}]}}),
    ],
)
def test_leaf_translation(cond, expected):
    body = to_opensearch(parse_query({"where": cond}, REG))
    assert body["query"]["bool"]["filter"] == [expected]


# ------------------------------------------------------------- evaluation ---
@pytest.mark.parametrize(
    "doc, expected",
    [
        ({"rule": {"level": 12}, "agent": {"id": "002"}}, True),
        ({"rule": {"level": 12}, "agent": {"id": "001"}}, True),
        ({"rule": {"level": 12}, "agent": {"id": "003"}}, False),
        ({"rule": {"level": 5}, "agent": {"id": "001"}}, False),
        ({"rule.level": 10, "agent.id": "001"}, True),      # flat keys work too
        ({}, False),
    ],
)
def test_matches(doc, expected):
    q = parse_query(PAYLOAD, REG)
    assert matches(q.where, doc) is expected


def test_multi_valued_field_and_wildcard():
    q = parse_query(
        {"where": {"and": [
            {"field": "rule.groups", "operator": "eq", "value": "authentication_failed"},
            {"field": "agent.name", "operator": "wildcard", "value": "web-*"},
        ]}},
        REG,
    )
    assert matches(q.where, {"rule": {"groups": ["syslog", "authentication_failed"]},
                             "agent": {"name": "web-01"}})
    assert not matches(q.where, {"rule": {"groups": ["syslog"]}, "agent": {"name": "web-01"}})


# ------------------------------------------------------------------- meta ---
def test_registry_meta():
    meta = REG.meta()
    level = next(f for f in meta["fields"] if f["name"] == "rule.level")
    assert level["allowed_values"][:3] == [0, 1, 2]
    assert "wildcard" not in level["operators"]
