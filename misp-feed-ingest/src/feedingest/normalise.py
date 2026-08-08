"""
Turn whatever a feed publishes into one indicator shape.

This module is the point of the project. Pulling a feed is a GET. The work is
that every source describes the same three things (an indicator, what kind it
is, and how much to trust it) in a different vocabulary, and a SIEM downstream
needs one vocabulary.

Deliberately pure: no network, no MISP client, no clock. That makes it testable
without either, which is why the tests can assert real behaviour rather than
mock a transport.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

log = logging.getLogger(__name__)

# MISP attribute types this pipeline emits. Anything a feed calls by another
# name is mapped onto one of these or dropped, because an indicator whose type
# the SIEM does not recognise is an indicator nobody will ever query.
MISP_TYPES = {"ip-dst", "ip-src", "domain", "hostname", "url", "md5", "sha1",
              "sha256", "email-src", "filename"}

# Feeds name types inconsistently. ThreatFox says "ip:port", OTX says "IPv4".
TYPE_ALIASES = {
    "ip": "ip-dst", "ipv4": "ip-dst", "ipv6": "ip-dst", "ip:port": "ip-dst",
    "ip-dst|port": "ip-dst", "ipv4-addr": "ip-dst",
    "domain": "domain", "hostname": "hostname", "fqdn": "domain",
    "url": "url", "uri": "url",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "filehash-md5": "md5", "filehash-sha1": "sha1", "filehash-sha256": "sha256",
    "email": "email-src", "email-src": "email-src",
}

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.IGNORECASE)

# Indicators that are technically valid and operationally useless. Ingesting
# these is how a feed pipeline generates its own alert fatigue.
NOISE = {
    "0.0.0.0", "127.0.0.1", "::1", "localhost", "example.com",
    "example.org", "8.8.8.8", "1.1.1.1",
}


class NormalisationError(ValueError):
    """Raised when a record cannot be turned into an indicator."""


@dataclass(frozen=True)
class Indicator:
    """One indicator, in the only shape the rest of the pipeline knows about."""

    value: str
    type: str
    source: str
    reliability: int
    tags: tuple[str, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        """Identity for deduplication: the same value and type from two feeds
        is one indicator with two sources, not two indicators."""
        return (self.value.lower(), self.type)

    def to_misp_attribute(self) -> dict[str, Any]:
        """
        Shape a MISP attribute. Kept as a plain dict so this module has no
        dependency on pymisp and can be tested without one.
        """
        return {
            "type": self.type,
            "value": self.value,
            "category": _category_for(self.type),
            "to_ids": self.reliability >= 80,
            "Tag": [{"name": t} for t in self.tags],
            "comment": f"{self.source} (reliability {self.reliability})",
        }


def _category_for(misp_type: str) -> str:
    if misp_type in {"md5", "sha1", "sha256", "filename"}:
        return "Payload delivery"
    if misp_type in {"email-src"}:
        return "Payload delivery"
    return "Network activity"


def infer_type(value: str) -> str | None:
    """
    Work out what an indicator is from its shape.

    Used when a feed does not say, which several do not. Returns None rather
    than guessing wildly, because a wrong type puts the indicator in a MISP
    category nobody searches.
    """
    v = value.strip()
    if not v:
        return None
    if HEX.match(v) and len(v) in HASH_LENGTHS:
        return HASH_LENGTHS[len(v)]
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if "@" in v and DOMAIN.match(v.rsplit("@", 1)[-1]):
        return "email-src"
    host = v.split(":", 1)[0] if v.count(":") == 1 and not v.startswith("[") else v
    try:
        ipaddress.ip_address(host)
        return "ip-dst"
    except ValueError:
        pass
    if DOMAIN.match(v):
        return "domain"
    return None


def canonical_type(raw: str | None, value: str) -> str | None:
    """Map a feed's type name onto a MISP type, falling back to inference."""
    if raw:
        mapped = TYPE_ALIASES.get(raw.strip().lower())
        if mapped in MISP_TYPES:
            return mapped
        if raw.strip().lower() in MISP_TYPES:
            return raw.strip().lower()
    return infer_type(value)


def is_noise(value: str, itype: str) -> bool:
    """
    Indicators that would generate alerts nobody wants.

    Private and loopback ranges are the important case. A feed occasionally
    publishes RFC1918 addresses, and pushing those into a SIEM means alerting
    on your own network.
    """
    v = value.strip().lower()
    if v in NOISE:
        return True

    # A URL is only as routable as its host. http://127.0.0.1/x is a loopback
    # indicator wearing a URL costume, and it reached the SIEM until a test
    # caught it.
    host = v
    if itype == "url":
        host = urlsplit(v).hostname or ""
        if not host or host in NOISE:
            return True
    if itype in {"ip-dst", "ip-src", "url"}:
        candidate = host.split(":", 1)[0] if host.count(":") == 1 else host
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            # A URL with a domain host is fine; a bare IP field that will not
            # parse as an address is not.
            return itype != "url"
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
            return True
    return False


def normalise_record(record: dict[str, Any], source: dict[str, Any]) -> Indicator:
    """
    Turn one raw feed record into an Indicator.

    Raises NormalisationError with a reason, so a caller can count why records
    were dropped rather than only that they were.
    """
    field_name = source.get("indicator_field")
    if not field_name:
        raise NormalisationError(f"{source['id']}: no indicator_field configured")

    raw_value = record.get(field_name)
    if raw_value is None or not str(raw_value).strip():
        raise NormalisationError("empty indicator value")
    value = str(raw_value).strip().strip('"')

    raw_type = None
    if source.get("indicator_type_field"):
        raw_type = record.get(source["indicator_type_field"])
    elif source.get("indicator_type"):
        raw_type = source["indicator_type"]

    itype = canonical_type(raw_type, value)
    if itype is None:
        raise NormalisationError(f"unrecognised indicator type for {value!r}")
    if is_noise(value, itype):
        raise NormalisationError(f"noise indicator {value!r}")

    context = {k: record[k] for k in source.get("context_fields", []) if k in record}

    return Indicator(
        value=value,
        type=itype,
        source=source["id"],
        reliability=int(source.get("reliability", 50)),
        tags=tuple(source.get("tags", ())),
        context=context,
    )


def passes_filter(record: dict[str, Any], source: dict[str, Any]) -> bool:
    """Apply a source's configured filter, if it has one."""
    f = source.get("filter")
    if not f:
        return True
    got = str(record.get(f["field"], "")).strip().strip('"').lower()
    return got == str(f["equals"]).strip().lower()


def normalise_all(records: Iterable[dict[str, Any]],
                  source: dict[str, Any]) -> tuple[list[Indicator], dict[str, int]]:
    """
    Normalise a feed's records, returning the indicators and a tally of why
    anything was dropped. The tally is the useful half: a feed that silently
    drops 90% of its records looks identical to one that works.
    """
    out: list[Indicator] = []
    dropped: dict[str, int] = {}
    for rec in records:
        if not passes_filter(rec, source):
            dropped["filtered"] = dropped.get("filtered", 0) + 1
            continue
        try:
            out.append(normalise_record(rec, source))
        except NormalisationError as exc:
            reason = str(exc).split(" ", 1)[0] if "noise" in str(exc) else "unparsed"
            dropped[reason] = dropped.get(reason, 0) + 1
            log.debug("%s: dropped record: %s", source["id"], exc)
    return out, dropped


def deduplicate(indicators: Iterable[Indicator]) -> list[Indicator]:
    """
    Collapse the same indicator seen in several feeds into one.

    The surviving copy keeps the highest reliability and the union of tags,
    because corroboration across independent sources is a reason to trust an
    indicator more, not a reason to store it twice.
    """
    best: dict[tuple[str, str], Indicator] = {}
    for ind in indicators:
        k = ind.key()
        cur = best.get(k)
        if cur is None:
            best[k] = ind
            continue
        merged_tags = tuple(sorted(set(cur.tags) | set(ind.tags)))
        winner = cur if cur.reliability >= ind.reliability else ind
        best[k] = Indicator(
            value=winner.value,
            type=winner.type,
            source=f"{cur.source},{ind.source}" if cur.source != ind.source else cur.source,
            reliability=max(cur.reliability, ind.reliability),
            tags=merged_tags,
            context={**cur.context, **ind.context},
        )
    return list(best.values())
