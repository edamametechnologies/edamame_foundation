Windows Detailed Score Privacy Policy with AI Details (EN)
==========================================================

By reporting a detailed score, you agree to share the following information with EDAMAME:
* Your machine unique identifier
* Your operating system name and version
* Your public IPv4 address and/or IPv6 address
* Your MAC address if available
* Your peer IDs for your VPN or ZTNA connections if available
* The domain you are connected to
* Your username in that domain
* Your score as a single numerical value
* Your score as a detailed vector of boolean values resulting on the following security checks:
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

* The details of each failing AI agent security check listed above:
  * For every AI coding agent EDAMAME supports, whether it is installed on this machine and whether its transcript observer is running
  * The name of the agent a failure belongs to, for example `cursor` or `claude_code`
  * The name of the governance harness that agent declares, for example `nono` or `srt`
  * The name of the risk amplifier that fired, for example `passwordless_root`, `critical_subprocess` or `secret_exposure`
  * The file name, without its path or its arguments, of a sensitive program the agent launched, for example `ssh`
  * The configured name of an MCP server found to be exposed, for example `gojiberry`, together with the exposure rule that fired, for example `mcp_public_no_strong_auth`. MCP servers that are not exposed are never named
  * The category of a secret found in the agent transcript, for example `aws_credentials`, never the secret itself

Agent transcripts, prompts, model responses, file contents, command arguments, environment variable values and secret values are never reported.

This information is used solely by EDAMAME and is not shared with any third party.

This information is gathered using a public "threat model" that is guaranteed not to violate your privacy.

The threat model can be seen at [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Windows.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Windows.json).

The threat model wiki can be seen at [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Windows-EN](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Windows-EN).

If you do not agree with this policy, please do not report your score.
