"""
PAN-OS Firewall Baseline Controls
==================================
Executable minimum security requirements for PAN-OS firewalls.
Each test maps to a specific security control (see README.md control catalog).

Run:
    uv run pytest tests/ -v
    uv run pytest tests/ -v -k "untrust or profile"
    uv run pytest tests/ --tb=short --junit-xml=baseline-report.xml
"""
import re
import yaml
import pytest
from pathlib import Path
from datetime import date

VSYS_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/vsys/entry[@name='vsys1']"
)

# Adapt these to match your firewall's zone names and profiles
ZONE_PROTECTION_PROFILES = {
    "L3-Outside": "zp-untrust",
    "L3-LAN10":   "zp-trust",
    "L3-INFRA":   "zp-trust",
    "L3-Guest":   "zp-midtrust",
    "L3-IOT":     "zp-midtrust",
}

# Rules that must always exist — adapt to your critical infrastructure rules
CRITICAL_RULES = [
    "ALLOW-Proxy-Local",
    "ALLOW - INFRA-IntraZ",
]

SERVICE_NAME_RE = re.compile(r"^(tcp|udp)-\d+")
SERVICE_ALLOWLIST = {"tcp-all"}  # built-in PAN-OS service, no port number


# ── Exception handling ─────────────────────────────────────────────────────


def load_exceptions(path="tests/exceptions.yaml"):
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text()) or {}
    return data.get("exceptions", []) or []


def is_excepted(rule_name: str, control_name: str, exceptions: list) -> bool:
    today = date.today()
    for exc in exceptions:
        if exc.get("rule") == rule_name and exc.get("control") == control_name:
            expires = date.fromisoformat(exc["expires"])
            if expires >= today:
                return True
    return False


# ── Smoke ──────────────────────────────────────────────────────────────────


def test_firewall_reachable(fw):
    root = fw.op("<show><system><info/></system></show>")
    assert root.attrib["status"] == "success"


def test_panos_version_meets_minimum(fw):
    root = fw.op("<show><system><info/></system></show>")
    version = root.findtext(".//sw-version")
    major, minor = (int(x) for x in version.split(".")[:2])
    assert (major, minor) >= (11, 1), \
        f"PAN-OS >= 11.1 required, running {version}"


# ── Security controls ──────────────────────────────────────────────────────


def test_deny_all_exists_for_untrust_zone(fw):
    """Control: explicit deny rule must cover traffic from the internet zone."""
    root = fw.config(f"{VSYS_XPATH}/rulebase/security/rules")
    deny_from_wan = [
        rule.get("name")
        for rule in root.findall(".//entry")
        if "L3-Outside" in [m.text for m in rule.findall(".//from/member")]
        and rule.findtext(".//action") == "deny"
    ]
    assert deny_from_wan, "CRITICAL: No explicit deny rule for untrust zone (L3-Outside)"


@pytest.mark.parametrize("zone,expected_profile", ZONE_PROTECTION_PROFILES.items())
def test_zone_protection_profile_applied(fw, zone, expected_profile):
    """Control: every zone must have the correct protection profile applied."""
    xpath = f"{VSYS_XPATH}/zone/entry[@name='{zone}']"
    root = fw.config(xpath)
    actual = root.findtext("./result/entry/network/zone-protection-profile")
    assert actual == expected_profile, \
        f"Zone {zone}: expected profile '{expected_profile}', got '{actual}'"


@pytest.mark.parametrize("rule_name", CRITICAL_RULES)
def test_critical_rule_exists(fw, rule_name):
    """Control: infrastructure-critical rules must not be accidentally deleted."""
    xpath = (
        f"{VSYS_XPATH}/rulebase/security/rules"
        f"/entry[@name='{rule_name}']"
    )
    root = fw.config(xpath)
    assert root.get("status") == "success" and root.find("./result/entry") is not None, \
        f"Critical rule '{rule_name}' is missing from the rulebase"


def test_no_unrestricted_allow_from_internet(fw):
    """Control: no rule may allow 'any' destination from the internet zone."""
    root = fw.config(f"{VSYS_XPATH}/rulebase/security/rules")
    violations = [
        rule.get("name")
        for rule in root.findall(".//entry")
        if "L3-Outside" in [m.text for m in rule.findall(".//from/member")]
        and "any" in [m.text for m in rule.findall(".//destination/member")]
        and rule.findtext(".//action") == "allow"
    ]
    assert not violations, \
        f"CRITICAL: Rules allow unrestricted internet access: {violations}"


def test_allow_rules_have_security_profile_group(fw):
    """Control: every allow rule must attach a security profile group.

    Rules without a profile group forward traffic with App-ID enforcement
    but zero Content-ID inspection (no AV, vuln protection, or URL filtering).
    Documented exceptions in tests/exceptions.yaml are respected until expiry.
    """
    exceptions = load_exceptions()
    root = fw.config(f"{VSYS_XPATH}/rulebase/security/rules")
    violations = [
        rule.get("name")
        for rule in root.findall(".//entry")
        if rule.findtext(".//action") == "allow"
        and rule.find(".//profile-setting/group") is None
        and not is_excepted(
            rule.get("name"),
            "test_allow_rules_have_security_profile_group",
            exceptions,
        )
    ]
    assert not violations, \
        f"Allow rules missing security profile group: {violations}"


def test_allow_rules_have_log_forwarding(fw):
    """Control: every allow rule must forward logs to the SIEM.

    Rules without log forwarding produce locally buffered logs only.
    Alerts fire inside the firewall but never reach threat detection.
    """
    exceptions = load_exceptions()
    root = fw.config(f"{VSYS_XPATH}/rulebase/security/rules")
    violations = [
        rule.get("name")
        for rule in root.findall(".//entry")
        if rule.findtext(".//action") == "allow"
        and not rule.findtext(".//log-setting")
        and not is_excepted(
            rule.get("name"),
            "test_allow_rules_have_log_forwarding",
            exceptions,
        )
    ]
    assert not violations, \
        f"Allow rules missing log forwarding profile: {violations}"


# ── Hygiene controls ───────────────────────────────────────────────────────


def test_service_objects_follow_naming_convention(fw):
    """Control: service objects must follow tcp-PORT or udp-PORT naming."""
    root = fw.config(f"{VSYS_XPATH}/service")
    violations = [
        svc.get("name")
        for svc in root.findall(".//entry")
        if svc.get("name") not in SERVICE_ALLOWLIST
        and not SERVICE_NAME_RE.match(svc.get("name", ""))
    ]
    assert not violations, \
        f"Service objects violate naming convention (tcp-PORT/udp-PORT): {violations}"
