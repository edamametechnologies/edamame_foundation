macOS Detailed Score Privacy Policy with AI Details (EN)
========================================================

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
  * Response to ping enabled
  * MDM profiles installed
  * JAMF remote administration enabled
  * Wake On LAN enabled
  * Manual Appstore updates
  * Local firewall disabled
  * Automatic login enabled
  * Remote login enabled
  * Remote desktop enabled
  * File sharing enabled
  * Remote events enabled
  * Corporate disk recovery key
  * Disk encryption disabled
  * Unsigned applications allowed
  * Manual system updates
  * Screen lock disabled
  * No antivirus enabled
  * No password manager installed
  * System Integrity Protection disabled
  * Guest account enabled
  * Root user enabled
  * Unprotected system changes
  * Potentially compromised email address
  * Unverified or unsafe network environment
  * Unverified or unsafe services exposed to the LAN
  * Unverified or anomalous traffic
  * Unreviewed vulnerability findings
  * Behavioral divergence detected
  * Escalated actions pending review
  * Your OS is not up to date
  * Chrome browser not up to date
  * Business rule not respected
  * CLI not restricted for standard users
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

* The AI details of this machine:
  * AI setup of this machine, sent in every report, even when no AI check is failing
    * The name of the user account EDAMAME assessed (taken from the home folder), the operating system family, and whether that account is an administrator, runs elevated or can become root without a password
    * The governance harnesses EDAMAME knows, for example `nono` or `srt`, and whether each one is installed
    * For every AI coding agent EDAMAME supports, for example `cursor` or `claude_code`:
      * Whether it is installed and whether its transcript observer is running
      * Whether it runs in a sandbox, the sandbox mechanism and its file access scope
      * Which risk amplifiers apply, for example `passwordless_root`, `critical_subprocess` or `secret_exposure`
      * The file names, without paths or arguments, of the sensitive programs it launched, for example `ssh`
      * The categories of secrets found in its transcripts, for example `aws_credentials`, never the secrets themselves
      * Every MCP server it declares, whether exposed or not: the configured server name, the transport, the exposure scope, the authentication strength, whether it is EDAMAME's own server, and the severity and rule names of any risk found on it
  * For each failing AI agent security check
    * The name of the check, the agent it concerns, and the conditions that made it fail: a risk amplifier, a sensitive program name, an MCP server name and exposure rule, a secret category, a missing or bypassed governance harness, or a paused transcript observer
    * For each attack pattern finding: the detector that raised it, its identifier (a hash), its severity, the detector's description, the name of the process and of its parent process, the destination domain name (or, when there is none, the destination IP address) and port, the detection basis, the framework reference, whether you dismissed it on this device, and whether an AI model reviewed it. The description can contain full file and program paths, which often include your user account name, and, when an AI agent re-ran a denied command under another spelling, both commands
    * For each behavioral divergence finding: its category, identifier, severity, description, the process name, the agent concerned, what triggered it, and the number of unexpected sensitive files (not their paths)
    * For each Assistant action waiting for your review: its identifier, its type and its priority
    * Whether the attack pattern detector, the divergence engine or the Assistant is switched off

Agent transcripts, prompts, model responses, file contents, environment variable values and secret values are never reported.

This information is used solely by EDAMAME and is not shared with any third party.

This information is gathered using a public "threat model" that is guaranteed not to violate your privacy.

The threat model can be seen at [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-macOS.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-macOS.json).

The threat model wiki can be seen at [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-macOS-EN](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-macOS-EN).

If you do not agree with this policy, please do not report your score.
