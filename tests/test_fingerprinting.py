import asyncio
import json
import logging
import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scada_scanner import (  # noqa: E402
    INSECURE_PROTOCOL_BASE_RISK,
    SCADA_PORTS,
    SCADAScanner,
    ScanConfig,
    PortProtocol,
)


@pytest.fixture(autouse=True)
def silence_logs():
    """Keep test output quiet."""
    logging.getLogger().setLevel(logging.CRITICAL)
    yield
    logging.getLogger().setLevel(logging.INFO)


@pytest.fixture
def scanner():
    cfg = ScanConfig(show_banner=False, verbosity=0, safe_mode=True, rate_limit=5.0)
    return SCADAScanner(cfg)


def test_identify_protocol_modbus(scanner):
    response = b"\x00\x01\x00\x00\x00\x01\x01"
    proto = scanner._identify_protocol(response)
    assert proto is not None
    assert proto["protocol"] == "MODBUS"
    assert proto["evidence"]


def test_port_hint_used_when_no_signature(scanner):
    port = next(p for p in SCADA_PORTS if p.port == 502)
    fingerprint = asyncio.run(
        scanner._fingerprint_service("127.0.0.1", port, {"response": "deadbeef"})
    )
    assert fingerprint["protocol"] == "MODBUS"
    assert fingerprint["confidence"] >= 0.35
    # Port hint is recorded as evidence
    assert any("port_hint" in e for e in fingerprint.get("evidence", []))


def test_vendor_identification_siemens(scanner):
    response = b"Copyright Siemens SIMATIC S7-300"
    vendor = scanner._identify_vendor(response)
    assert vendor is not None
    assert vendor["vendor"] == "SIEMENS"
    assert vendor["product"] == "S7-300"


def test_risk_score_includes_base_risk(scanner):
    fingerprint = {
        "protocol": "MODBUS",
        "vulnerabilities": [],
        "version": "Unknown",
        "behaviors": [],
    }
    score = scanner._calculate_risk_score(fingerprint)
    assert score >= INSECURE_PROTOCOL_BASE_RISK["MODBUS"]


def test_unexpected_port_sets_flag_and_finding(scanner):
    modbus_like = b"\x00\x01\x00\x00\x00\x01\x01"
    odd_port = PortProtocol(44818, "TCP", "EIP", "EtherNet/IP")
    fp = asyncio.run(
        scanner._fingerprint_service(
            "127.0.0.1", odd_port, {"response": modbus_like.hex()}
        )
    )
    assert fp["unexpected_port"] is True
    assert any("unexpected port" in f.lower() for f in fp["findings"])
    assert fp["risk_score"] >= INSECURE_PROTOCOL_BASE_RISK["MODBUS"]


def test_vulnx_lookup_parses_results(scanner, monkeypatch):
    sample = [{"id": "CVE-2024-9999", "description": "Sample vuln", "severity": "high"}]

    class DummyProc:
        def __init__(self):
            self.returncode = 0

        async def communicate(self):
            return json.dumps(sample).encode(), b""

    async def fake_exec(*args, **kwargs):  # pylint: disable=unused-argument
        return DummyProc()

    monkeypatch.setattr(scanner, "_vulnx_available", lambda: True)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    vulns = asyncio.run(scanner._lookup_vulnx_vulns("MODBUS", "Schneider", "M340", "2.6.0"))
    assert vulns
    assert vulns[0]["cve_id"] == "CVE-2024-9999"
    assert vulns[0]["source"] == "vulnx"


def test_local_vuln_db_matches_updated_entries(scanner):
    vulns = scanner._check_vulnerabilities(
        "MODBUS", "Socomec", "Socomec DIRIS Digiware M-70", "1.6.9"
    )
    cve_ids = {v.cve_id for v in vulns}
    assert "CVE-2025-55221" in cve_ids


def test_unique_vulns_deduplicates(monkeypatch):
    from scada_scanner import _unique_vulns

    data = [
        {"cve_id": "CVE-1", "severity": "high"},
        {"cve_id": "CVE-1", "severity": "high"},
        {"id": "CVE-2", "severity": "medium"},
    ]
    unique = _unique_vulns(data)
    assert len(unique) == 2


def test_risk_score_unexpected_port_bump(scanner):
    base_fp = {
        "protocol": "MODBUS",
        "vulnerabilities": [],
        "version": "1.0",
        "behaviors": [],
        "unexpected_port": False,
    }
    bumped_fp = dict(base_fp)
    bumped_fp["unexpected_port"] = True

    base_score = scanner._calculate_risk_score(base_fp)
    bumped_score = scanner._calculate_risk_score(bumped_fp)
    assert bumped_score > base_score
