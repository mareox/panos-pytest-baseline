# Security

## Do not commit real firewall configs

This repo contains only synthetic XML fixtures for demonstration.

**Never commit:**
- Real firewall XML exports (`*.xml` from an actual device)
- API keys or credentials
- Real hostnames, IP addresses, zone names, object names, or business-context naming
- Panorama serial numbers, template names, or device group names

## Credentials

Always use a **read-only API user** with minimum required permissions.
Store credentials in environment variables or `.env` (gitignored), never in code.

## Reporting issues

If you discover a security issue in this project, open a GitHub issue or contact the author directly.
