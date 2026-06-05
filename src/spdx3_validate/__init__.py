# SPDX-FileCopyrightText: 2024 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""spdx3-validate: SPDX 3 validation library and CLI tool."""

from .version import VERSION as __version__
from .errors import SchemaError, Spdx3ValidateError, UnsupportedVersionError
from .result import MergedResult, Result
from .main import main, spdx3validate

__all__ = [
    "__version__",
    "MergedResult",
    "Result",
    "SchemaError",
    "Spdx3ValidateError",
    "UnsupportedVersionError",
    "main",
    "spdx3validate",
]
