"""Access the bundled authoritative RangeSpec JSON Schema."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import cast

from jsonschema import Draft202012Validator

from rangespec.types import JSONObject

SCHEMA_RESOURCE = "rangespec-v0.1.schema.json"


@lru_cache(maxsize=1)
def load_schema() -> JSONObject:
    """Load and self-validate the package's version 0.1 JSON Schema.

    Returns:
        A parsed schema object cached for the process lifetime.

    Raises:
        json.JSONDecodeError: If the bundled resource is corrupted.
        jsonschema.exceptions.SchemaError: If it is not a valid Draft 2020-12
            schema. These indicate a broken package rather than user input.
    """

    schema_text = (
        resources.files("rangespec")
        .joinpath("data")
        .joinpath(SCHEMA_RESOURCE)
        .read_text(encoding="utf-8")
    )
    schema = cast(JSONObject, json.loads(schema_text))
    Draft202012Validator.check_schema(schema)
    return schema


def schema_text() -> str:
    """Return the bundled schema in stable reviewed formatting."""

    return json.dumps(load_schema(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
