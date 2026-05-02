import os
import pytest
import requests
import xml.etree.ElementTree as ET
import urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VSYS_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/vsys/entry[@name='vsys1']"
)

def _load_env(path=".env"):
    env = {}
    p = Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


class PanOSClient:
    """Read-only live client for the PAN-OS XML API."""

    def __init__(self, host: str, key: str):
        self.base = f"https://{host}/api/"
        self.key = key
        self.session = requests.Session()
        self.session.verify = False

    def op(self, cmd: str) -> ET.Element:
        r = self.session.get(self.base, params={
            "type": "op", "cmd": cmd, "key": self.key,
        }, timeout=30)
        r.raise_for_status()
        return ET.fromstring(r.text)

    def config(self, xpath: str) -> ET.Element:
        r = self.session.get(self.base, params={
            "type": "config", "action": "show",
            "xpath": xpath, "key": self.key,
        }, timeout=30)
        r.raise_for_status()
        return ET.fromstring(r.text)


class FixturePanOSClient:
    """Fixture-based client that reads synthetic XML files instead of a live firewall.

    Enables running the full control suite without firewall access.
    Set PANOS_FIXTURE_DIR=examples/fixtures to activate.
    """

    def __init__(self, fixture_dir: str):
        self.dir = Path(fixture_dir)

    def _load(self, filename: str) -> ET.Element:
        path = self.dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Fixture not found: {path}")
        return ET.parse(path).getroot()

    def op(self, cmd: str) -> ET.Element:
        if "system" in cmd and "info" in cmd:
            return self._load("system-info.xml")
        raise NotImplementedError(f"No fixture for op command: {cmd}")

    def config(self, xpath: str) -> ET.Element:
        # Route XPath to appropriate fixture file.
        # Use rsplit to get the last entry[@name=...] in the xpath, since the
        # vsys path prefix also contains entry[@name='localhost.localdomain'].
        if "rulebase/security/rules/entry[@name=" in xpath:
            # Specific named rule lookup
            name = xpath.rsplit("entry[@name='", 1)[1].split("'")[0]
            safe = name.replace(" ", "-").replace("/", "-")
            filename = f"rule-{safe}.xml"
            if not (self.dir / filename).exists():
                # Return "not found" response
                return ET.fromstring('<response status="error" code="7"><msg>Object doesn\'t exist</msg></response>')
            return self._load(filename)
        elif "rulebase/security/rules" in xpath:
            return self._load("security-rules.xml")
        elif "zone/entry[@name=" in xpath:
            zone = xpath.rsplit("entry[@name='", 1)[1].split("'")[0]
            return self._load(f"zone-{zone}.xml")
        elif xpath.endswith("/service"):
            return self._load("service-objects.xml")
        raise NotImplementedError(f"No fixture mapping for xpath: {xpath}")


@pytest.fixture(scope="session")
def fw():
    """Session-scoped PAN-OS client. Supports live and fixture modes."""
    fixture_dir = os.environ.get("PANOS_FIXTURE_DIR")
    if fixture_dir:
        return FixturePanOSClient(fixture_dir=fixture_dir)

    dotenv = _load_env()
    host = os.environ.get("FW_HOST") or dotenv.get("firewall-ip")
    key = os.environ.get("PANOS_KEY") or dotenv.get("ro-api-key")

    if not host or not key:
        pytest.skip(
            "No credentials found. Set FW_HOST + PANOS_KEY for live mode, "
            "or PANOS_FIXTURE_DIR=examples/fixtures for demo mode."
        )

    return PanOSClient(host=host, key=key)
