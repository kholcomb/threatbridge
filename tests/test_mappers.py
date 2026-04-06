"""Tests for CWE mapper."""

import pytest

from cve_intel.mappers.cwe_to_attack import map_cwe_to_attack


def test_cwe_787_maps_to_t1203_and_t1068(mock_attack_data):
    mapping = map_cwe_to_attack("CVE-2024-21762", ["CWE-787"], mock_attack_data)
    ids = mapping.technique_ids
    assert "T1203" in ids
    assert "T1068" in ids


def test_unknown_cwe_produces_empty_mapping(mock_attack_data):
    mapping = map_cwe_to_attack("CVE-2024-0001", ["CWE-9999"], mock_attack_data)
    assert mapping.techniques == []


def test_cwe_mapping_method_is_static(mock_attack_data):
    mapping = map_cwe_to_attack("CVE-2024-0001", ["CWE-787"], mock_attack_data)
    assert mapping.mapping_method == "cwe_static"
