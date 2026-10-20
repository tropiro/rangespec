"""RangeSpec public package surface.

RangeSpec validates versioned authorization manifests for controlled security
ranges. Importing this package performs no I/O and creates no network clients.
"""

from rangespec.canonical import fingerprint
from rangespec.io import load_json
from rangespec.validation import Issue, ValidationReport, validate_manifest

__all__ = [
    "Issue",
    "ValidationReport",
    "fingerprint",
    "load_json",
    "validate_manifest",
]

__version__ = "0.2.1"
