# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Structured results returned by spdx3validate()."""

import contextlib

from dataclasses import dataclass, field
from typing import Callable, ContextManager, Iterator, List, Optional, Protocol

from jsonschema.exceptions import ValidationError


class Spinner(Protocol):
    """Minimal progress-spinner interface used by the validator."""

    def succeed(self, text: Optional[str] = ...) -> None: ...

    def fail(self, text: Optional[str] = ...) -> None: ...


#: A factory ``progress(text)`` yielding a :class:`Spinner` context manager.
ProgressFactory = Callable[[str], ContextManager[Spinner]]


@dataclass
class Result:
    """Validation outcome for a single input document."""

    location: str
    load_errors: List[str] = field(default_factory=list)
    schema_errors: List[ValidationError] = field(default_factory=list)
    shacl_errors: List[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not (self.load_errors or self.schema_errors or self.shacl_errors)


@dataclass
class MergedResult:
    """Aggregate validation outcome across all input documents.

    Holds a :class:`Result` per input document, plus the SHACL errors of the
    merged document (the union of all inputs) -- the same kind of content as
    :attr:`Result.shacl_errors`.
    """

    results: List[Result] = field(default_factory=list)
    shacl_errors: List[str] = field(default_factory=list)
    merged_skipped: bool = False

    @property
    def valid(self) -> bool:
        return all(r.valid for r in self.results) and not self.shacl_errors

    def __bool__(self) -> bool:
        return self.valid


class _NullSpinner:
    """No-op stand-in for a halo spinner when no progress reporter is used."""

    def succeed(self, text: Optional[str] = None) -> None:
        pass

    def fail(self, text: Optional[str] = None) -> None:
        pass


@contextlib.contextmanager
def null_progress(text: str) -> Iterator[_NullSpinner]:
    """Default progress factory: report nothing."""
    yield _NullSpinner()
