"""Filter observations by terms found in the hostname."""
from __future__ import annotations

import os
from typing import Iterable, Iterator

from scanner.ct.models import Observation


def _a_label(text: str) -> str:
    if text.isascii():
        return text
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return text


def _variants(term: str) -> frozenset[str]:
    """The term plus its A-label spellings, since names are matched in punycode form."""
    variants = {term}
    if not term.isascii():
        variants.add(".".join(_a_label(label) for label in term.split(".")))
        variants.add(".".join("-".join(_a_label(part) for part in label.split("-")) for label in term.split(".")))
    return frozenset(variants)


class TermFilter:
    """Case-insensitive term matching on hostnames.

    Hostnames are matched in their A-label (punycode) form, so a term with non-ASCII characters is also matched by
    its IDNA encoding. By default a term matches anywhere in the name. With ``label_boundary`` it must equal a whole
    label, one hyphen-separated part of a label or a run of consecutive hyphen-separated parts within one label
    (a term with dots must equal a run of whole labels).
    """

    def __init__(self, terms: Iterable[str], label_boundary: bool = False) -> None:
        seen: dict[str, None] = {}
        for term in terms:
            term = term.strip().lower()
            if term:
                seen.setdefault(term)
        self.terms: tuple[str, ...] = tuple(seen)
        self._variants: tuple[frozenset[str], ...] = tuple(_variants(term) for term in self.terms)
        self.label_boundary = label_boundary

    @classmethod
    def from_terms(cls, terms: Iterable[str], label_boundary: bool = False) -> "TermFilter":
        return cls(terms, label_boundary=label_boundary)

    @classmethod
    def from_file(cls, path: str | os.PathLike, label_boundary: bool = False) -> "TermFilter":
        """One term per line; blank lines and lines starting with ``#`` are skipped.

        Raises ``ValueError`` if the file holds no terms, because an empty filter would drop every observation.
        """
        with open(path, "r", encoding="utf-8-sig") as handle:
            lines = [line.strip() for line in handle]
        terms = [line for line in lines if line and not line.startswith("#")]
        if not terms:
            raise ValueError(f"no terms in {path}")
        return cls(terms, label_boundary=label_boundary)

    def matches(self, name: str) -> list[str]:
        """The terms that match ``name``, in the order they were given."""
        lowered = name.strip().lower()
        if not self.label_boundary:
            return [term for term, variants in zip(self.terms, self._variants)
                    if any(variant in lowered for variant in variants)]
        padded_labels = ["-" + label + "-" for label in lowered.split(".")]
        dotted = "." + lowered + "."

        def hit(variant: str) -> bool:
            if "." in variant:
                return "." + variant + "." in dotted
            needle = "-" + variant + "-"
            return any(needle in label for label in padded_labels)

        return [term for term, variants in zip(self.terms, self._variants) if any(hit(v) for v in variants)]

    def filter(self, observations: Iterable[Observation]) -> Iterator[Observation]:
        for obs in observations:
            if self.matches(obs.name):
                yield obs
