"""
api.py: FastAPI wrapper.

Run:   uvicorn api:app --reload
Try:   curl -X POST localhost:8000/search/preview -H 'content-type: application/json' -d @payload.json

FastAPI cannot forward a validation `context` when it parses the body for you,
so the endpoints accept a plain dict and call parse_query() themselves.
"""

from typing import Any

from fastapi import Body, FastAPI, HTTPException
from pydantic import ValidationError

from query_engine import (
    QueryTooComplex,
    build_wazuh_registry,
    parse_query,
    to_opensearch,
)

app = FastAPI(title="Wazuh query API")
REGISTRY = build_wazuh_registry()


def _parse_or_422(payload: dict[str, Any]):
    try:
        return parse_query(payload, REGISTRY)
    except QueryTooComplex as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(include_url=False, include_context=False, include_input=False),
        )


@app.get("/search/meta")
def meta() -> dict[str, Any]:
    """Allowed fields, operators and values: drive the frontend filter builder from this."""
    return REGISTRY.meta()


@app.post("/search/preview")
def preview(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Validate and return the OpenSearch body without executing it."""
    q = _parse_or_422(payload)
    return {"index": q.index or REGISTRY.index, "body": to_opensearch(q)}


@app.post("/search")
async def search(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    q = _parse_or_422(payload)
    body = to_opensearch(q)

    # Plug in your client here, e.g. opensearch-py's AsyncOpenSearch:
    #   result = await client.search(index=q.index or REGISTRY.index, body=body)
    #   return result["hits"]
    return {"index": q.index or REGISTRY.index, "body": body, "note": "wire up OpenSearch client"}
