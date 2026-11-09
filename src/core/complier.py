
from enum import StrEnum


test_query = {
  "index": "wazuh-alerts-*",
  "where": {
    "field": "rule.level",
    "operator": "gte",
    "value": 10
  },
  "time_range": {
    "field": "@timestamp",
    "from": "now-24h",
    "to": "now"
  },
  "sort": {
    "field": "@timestamp",
    "order": "desc"
  },
  "pagination": {
    "limit": 100,
    "offset": 0
  }
}

class Operator(StrEnum):
    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NIN = "nin"

LIST_OPS = frozenset({Operator.IN, Operator.NIN})
RANGE_OPS = frozenset({Operator.GT, Operator.GTE, Operator.LT, Operator.LTE})
FLAT_OPS = frozenset({Operator.EQ, Operator.NEQ})

