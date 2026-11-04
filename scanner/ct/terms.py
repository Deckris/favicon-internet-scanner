"""Filter observations by terms found in the hostname."""
from __future__ import annotations

import os
from typing import Iterable, Iterator

from scanner.ct.models import Observation


class TermFilter:
    """Case-insensitive term matching on hostnames.

    By default a term matches anywhere in the name. With ``label_boundary`` it must equal a whole label or one
    hyphen-separated part of a label (a term with dots must equal a run of whole labels).
    """

    def __init__(self, terms: Iterable[str], label_boundary: bool = False) -> None:
        seen: dict[str, None] = {}
        for term in terms:
            term = term.strip().lower()
            if term:
                seen.setdefault(term)
        self.terms: tuple[str, ...] = tuple(seen)
        self.label_boundary = label_boundary

    @classmethod
    def from_terms(cls, terms: Iterable[str], label_boundary: bool = False) -> "TermFilter":
        return cls(terms, label_boundary=label_boundary)

    @classmethod
    def from_file(cls, path: str | os.PathLike, label_boundary: bool = False) -> "TermFilter":
        """One term per line; blank lines and lines starting with ``#`` are skipped."""
        with open(path, "r", encoding="utf-8") as handle:
            lines = [line.strip() for line in handle]
        return cls((line for line in lines if line and not line.startswith("#")), label_boundary=label_boundary)

    def matches(self, name: str) -> list[str]:
        """The terms that match ``name``, in the order they were given."""
        lowered = name.strip().lower()
        if not self.label_boundary:
            return [term for term in self.terms if term in lowered]
        labels = lowered.split(".")
        parts = {part for label in labels for part in label.split("-")} | set(labels)
        dotted = "." + lowered + "."
        return [term for term in self.terms if term in parts or ("." in term and "." + term + "." in dotted)]

    def filter(self, observations: Iterable[Observation]) -> Iterator[Observation]:
        for obs in observations:
            if self.matches(obs.name):
                yield obs
