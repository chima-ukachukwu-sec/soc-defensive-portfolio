"""
Tests for indicator normalisation.

These are the tests worth having. Fetching is a GET and either works or does
not; the part that quietly ruins a threat-intel pipeline is a feed whose
records get misparsed into indicators of the wrong type, or private addresses
reaching a SIEM and alerting on your own network.

No network is touched here, which is why normalise.py has no transport in it.
"""

from __future__ import annotations

import pytest

from feedingest.normalise import (Indicator, NormalisationError, canonical_type,
                                  deduplicate, infer_type, is_noise,
                                  normalise_all, normalise_record,
                                  passes_filter)

URLHAUS = {
    "id": "urlhaus", "reliability": 85, "tags": ["source:urlhaus"],
    "indicator_field": "url", "indicator_type": "url",
    "filter": {"field": "url_status", "equals": "online"},
}
THREATFOX = {
    "id": "threatfox", "reliability": 80, "tags": ["source:threatfox"],
    "indicator_field": "ioc", "indicator_type_field": "ioc_type",
    "context_fields": ["malware_printable"],
}


# --- type inference ------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("8.8.4.4", "ip-dst"),
    ("2001:4860:4860::8844", "ip-dst"),
    ("evil.example.net", "domain"),
    ("http://bad.test/payload.exe", "url"),
    ("https://bad.test/x", "url"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("phish@bad.test", "email-src"),
])
def test_infer_type_from_shape(value, expected):
    assert infer_type(value) == expected


@pytest.mark.parametrize("value", ["", "   ", "not a thing", "12345"])
def test_infer_type_returns_none_rather_than_guessing(value):
    assert infer_type(value) is None


def test_hash_length_decides_hash_type():
    """A 63-character hex string is not a sha256 and must not be called one."""
    assert infer_type("a" * 64) == "sha256"
    assert infer_type("a" * 63) is None


@pytest.mark.parametrize("raw,expected", [
    ("IPv4", "ip-dst"), ("ip:port", "ip-dst"), ("FQDN", "domain"),
    ("filehash-sha256", "sha256"), ("url", "url"),
])
def test_feed_type_names_map_onto_misp_types(raw, expected):
    assert canonical_type(raw, "placeholder") == expected


def test_unknown_feed_type_falls_back_to_inference():
    assert canonical_type("mystery-type", "9.9.9.9") == "ip-dst"


# --- noise suppression ---------------------------------------------------

@pytest.mark.parametrize("value", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.4.2", "0.0.0.0",
    "8.8.8.8", "localhost", "example.com",
])
def test_noise_and_private_space_is_rejected(value):
    """Pushing RFC1918 into a SIEM means alerting on your own network."""
    assert is_noise(value, infer_type(value) or "ip-dst")


def test_loopback_inside_a_url_is_still_noise():
    """A URL is only as routable as its host."""
    assert is_noise("http://127.0.0.1/payload", "url")
    assert is_noise("http://10.0.0.5:8080/x", "url")
    assert not is_noise("http://bad.example.net/payload", "url")


def test_routable_address_is_not_noise():
    assert not is_noise("45.83.64.1", "ip-dst")
    assert not is_noise("evil.example.net", "domain")


# --- record normalisation ------------------------------------------------

def test_normalise_urlhaus_record():
    ind = normalise_record({"url": "http://bad.test/x.exe", "url_status": "online"},
                           URLHAUS)
    assert ind.type == "url"
    assert ind.reliability == 85
    assert "source:urlhaus" in ind.tags


def test_normalise_uses_per_record_type_when_feed_provides_one():
    ind = normalise_record({"ioc": "45.83.64.1", "ioc_type": "ip:port"}, THREATFOX)
    assert ind.type == "ip-dst"


def test_context_fields_are_carried_through():
    ind = normalise_record(
        {"ioc": "bad.test", "ioc_type": "domain", "malware_printable": "Emotet",
         "ignored": "x"}, THREATFOX)
    assert ind.context == {"malware_printable": "Emotet"}


def test_empty_value_is_rejected_with_a_reason():
    with pytest.raises(NormalisationError, match="empty"):
        normalise_record({"url": "   ", "url_status": "online"}, URLHAUS)


def test_unrecognised_value_is_rejected():
    with pytest.raises(NormalisationError, match="unrecognised"):
        normalise_record({"ioc": "???", "ioc_type": "nonsense"}, THREATFOX)


def test_quotes_are_stripped():
    ind = normalise_record({"url": '"http://bad.test/x"', "url_status": "online"},
                           URLHAUS)
    assert not ind.value.startswith('"')


# --- filtering -----------------------------------------------------------

def test_offline_urls_are_filtered_out():
    """Historical indicators fill a SIEM with things that will never fire."""
    assert passes_filter({"url_status": "online"}, URLHAUS)
    assert not passes_filter({"url_status": "offline"}, URLHAUS)


def test_filter_is_case_and_quote_insensitive():
    assert passes_filter({"url_status": '"ONLINE"'}, URLHAUS)


# --- batch behaviour and drop accounting ---------------------------------

def test_normalise_all_reports_why_records_were_dropped():
    """A feed that silently drops most records looks like one that works."""
    records = [
        {"url": "http://bad.test/a", "url_status": "online"},
        {"url": "http://old.test/b", "url_status": "offline"},
        {"url": "", "url_status": "online"},
        {"url": "http://127.0.0.1/c", "url_status": "online"},
    ]
    inds, dropped = normalise_all(records, URLHAUS)
    assert len(inds) == 1
    assert dropped.get("filtered") == 1
    assert sum(dropped.values()) == 3


# --- deduplication -------------------------------------------------------

def test_same_indicator_from_two_feeds_becomes_one():
    a = Indicator("bad.test", "domain", "urlhaus", 85, ("source:urlhaus",))
    b = Indicator("BAD.TEST", "domain", "threatfox", 90, ("source:threatfox",))
    out = deduplicate([a, b])
    assert len(out) == 1


def test_deduplication_keeps_the_higher_reliability_and_merges_tags():
    a = Indicator("bad.test", "domain", "urlhaus", 85, ("source:urlhaus",))
    b = Indicator("bad.test", "domain", "threatfox", 90, ("source:threatfox",))
    merged = deduplicate([a, b])[0]
    assert merged.reliability == 90
    assert set(merged.tags) == {"source:urlhaus", "source:threatfox"}
    assert "urlhaus" in merged.source and "threatfox" in merged.source


def test_different_types_are_not_merged():
    a = Indicator("bad.test", "domain", "x", 50)
    b = Indicator("bad.test", "hostname", "y", 50)
    assert len(deduplicate([a, b])) == 2


# --- MISP attribute shape ------------------------------------------------

def test_to_ids_follows_reliability():
    """
    to_ids drives whether a SIEM alerts on an indicator. Low-confidence
    sources should land in MISP for context without generating alerts.
    """
    assert Indicator("bad.test", "domain", "x", 90).to_misp_attribute()["to_ids"]
    assert not Indicator("bad.test", "domain", "x", 40).to_misp_attribute()["to_ids"]


def test_attribute_category_matches_type():
    assert Indicator("a" * 32, "md5", "x", 90).to_misp_attribute()["category"] == "Payload delivery"
    assert Indicator("bad.test", "domain", "x", 90).to_misp_attribute()["category"] == "Network activity"


def test_attribute_records_its_source():
    attr = Indicator("bad.test", "domain", "urlhaus", 85).to_misp_attribute()
    assert "urlhaus" in attr["comment"]
