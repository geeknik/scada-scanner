import asyncio
import logging
import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scada_scanner import (  # noqa: E402
    SCADAScanner,
    ScanConfig,
    SCADA_PORTS,
    INSECURE_PROTOCOL_BASE_RISK,
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


def test_port_hint_used_when_no_signature(scanner):
    port = next(p for p in SCADA_PORTS if p.port == 502)
    fingerprint = asyncio.run(
        scanner._fingerprint_service("127.0.0.1", port, {"response": "deadbeef"})
    )
    assert fingerprint["protocol"] == "MODBUS"
    assert fingerprint["confidence"] >= 0.35


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
