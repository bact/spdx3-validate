# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Exceptions raised by spdx3-validate.

These signal *operational* failures (the tool cannot perform validation),
as opposed to a document simply being invalid (reported via MergedResult).
"""


class Spdx3ValidateError(Exception):
    """Base class for all spdx3-validate operational errors."""


class UnsupportedVersionError(Spdx3ValidateError):
    """The requested SPDX version is unknown, or inputs mix incompatible versions."""


class SchemaError(Spdx3ValidateError):
    """The SPDX schema could not be fetched or is not usable for validation."""
