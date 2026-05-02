# Control Catalog

Each control maps a minimum security requirement to a pytest test function.

## Control IDs

| ID | Test | Requirement | Compliance Reference |
|---|---|---|---|
| PANOS-BL-001 | `test_firewall_reachable` | Firewall responds to API | Smoke test |
| PANOS-BL-002 | `test_panos_version_meets_minimum` | PAN-OS >= 11.1 | Patch compliance |
| PANOS-BL-003 | `test_deny_all_exists_for_untrust_zone` | Explicit deny rule covers internet zone | Defense in depth |
| PANOS-BL-004 | `test_zone_protection_profile_applied` | Zone protection profile applied to every zone | PCI-DSS 1.3 |
| PANOS-BL-005 | `test_critical_rule_exists` | Infrastructure-critical rules are not accidentally deleted | Change detection |
| PANOS-BL-006 | `test_no_unrestricted_allow_from_internet` | No allow rule permits any destination from internet zone | CIS PAN-OS Benchmark |
| PANOS-BL-007 | `test_allow_rules_have_security_profile_group` | Every allow rule has a security profile group (Content-ID inspection) | NIST CSF DE.CM-1 |
| PANOS-BL-008 | `test_allow_rules_have_log_forwarding` | Every allow rule forwards logs to SIEM | SOC 2 CC6.1, PCI-DSS 10.2 |
| PANOS-BL-009 | `test_service_objects_follow_naming_convention` | Service objects follow tcp-PORT / udp-PORT convention | Operational hygiene |

## Exception format

Controls that cannot currently be met should be documented in `tests/exceptions.yaml`:

```yaml
exceptions:
  - rule: ALLOW-Vendor-Temp
    control: test_allow_rules_have_security_profile_group
    owner: network-security
    ticket: CHG-12345
    expires: 2026-06-30
    reason: Vendor migration window
```

Expired exceptions automatically start failing again.

## Adding controls

See [CONTRIBUTING.md](../CONTRIBUTING.md).
