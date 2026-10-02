Windows Detailed Score Privacy Policy (EN)
==========================================

By reporting a detailed score, you agree to share the following information with EDAMAME:
* Your machine unique identifier
* Your machine name (hostname), without its network domain suffix
* Your operating system name and version
* Your public IPv4 address and/or IPv6 address
* Your approximate location derived from your public IPv4 address: city, region, country, time zone, latitude and longitude. To find it, EDAMAME sends your public IPv4 address to the ip-api.com geolocation service
* Your MAC address if available
* Your peer IDs for your VPN or ZTNA connections if available
* The domain you are connected to, your username in that domain and the access code used to connect
* The language of the EDAMAME interface
* The EDAMAME version, whether this machine is a CI/CD runner, and the state of the EDAMAME Helper
* The date and time of the report
* Your score as a single numerical value
* Your score for each category (network, system integrity, system services, applications, credentials), your star rating, and your compliance percentage for each compliance framework
* The history of the remediations and rollbacks you performed: the check concerned, the action, when it happened, and whether it succeeded and was validated
* The name, date and signature of the threat model used, and for each of the following security checks: its definition as published in that threat model, its status (failing, passing or unknown) and when it was last evaluated:
  * EDAMAME helper inactive
  * Cached logon credentials enabled
  * No antivirus enabled
  * No password manager installed
  * Disk encryption disabled
  * User Account Control disabled
  * Automatic logon enabled
  * Potentially compromised email address
  * Unverified or unsafe network environment
  * Unverified or unsafe services exposed to the LAN
  * Unverified or anomalous traffic
  * Unreviewed vulnerability findings
  * Behavioral divergence detected
  * Escalated actions pending review
  * Windows Script Host enabled
  * Remote Desktop Protocol (RDP) enabled
  * Windows Update disabled
  * Guest account enabled
  * Built-in Administrator account enabled
  * Windows Firewall disabled
  * Remote Registry Service enabled
  * LM and NTLMv1 protocols enabled
  * Lsass.exe process protection not enabled
  * PowerShell execution policy not securely configured
  * Chrome browser not up to date
  * SMBv1 Protocol Enabled
  * No sign-in options enabled
  * Windows Hello is not available
  * Screensaver lock is not properly configured
  * Business rule not respected
  * Cursor agent unsecured
  * Claude Code agent unsecured
  * Claude Desktop agent unsecured
  * OpenClaw agent unsecured
  * AI agent with high host blast radius
  * AI agents run without a governance harness
  * Agent escapes its governance harness boundary
  * AI agent exposes an unprotected MCP server
  * Codex CLI agent unsecured
  * Hermes agent unsecured

This information is used solely by EDAMAME and is not shared with any third party, apart from your public IPv4 address sent to ip-api.com for the location lookup above.

This information is gathered using a public "threat model" that is guaranteed not to violate your privacy.

The threat model can be seen at [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Windows.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Windows.json).

The threat model wiki can be seen at [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Windows-EN](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Windows-EN).

If you do not agree with this policy, please do not report your score.
