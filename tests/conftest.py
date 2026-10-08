"""Shared immutable fixture loading for RangeSpec behavior tests."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from rangespec.io import load_json
from rangespec.types import JSONObject

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def valid_manifest() -> JSONObject:
    """Return a fresh copy of the reviewed gateway example for each test."""

    manifest = load_json(PROJECT_ROOT / "examples" / "gateway-valid.json")
    return deepcopy(manifest)
