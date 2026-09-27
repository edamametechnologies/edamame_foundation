AI Failure Details Sharing Policy (EN)
======================================

When this device is connected to a domain, it sends score reports to EDAMAME Hub. This setting adds AI details to those reports. It is off unless you turn it on, and your score reports work without it.

By turning it on, you agree to share the following information with EDAMAME in each score report.

**AI setup of this machine, sent in every report, even when no AI check is failing**
* The name of the user account EDAMAME assessed (taken from the home folder), the operating system family, and whether that account is an administrator, runs elevated or can become root without a password
* The governance harnesses EDAMAME knows, for example `nono` or `srt`, and whether each one is installed
* For every AI coding agent EDAMAME supports, for example `cursor` or `claude_code`:
  * Whether it is installed and whether its transcript observer is running
  * Whether it runs in a sandbox, the sandbox mechanism and its file access scope
  * Which risk amplifiers apply, for example `passwordless_root`, `critical_subprocess` or `secret_exposure`
  * The file names, without paths or arguments, of the sensitive programs it launched, for example `ssh`
  * The categories of secrets found in its transcripts, for example `aws_credentials`, never the secrets themselves
  * Every MCP server it declares, whether exposed or not: the configured server name, the transport, the exposure scope, the authentication strength, whether it is EDAMAME's own server, and the severity and rule names of any risk found on it

**For each failing AI agent security check**
* The name of the check, the agent it concerns, and the conditions that made it fail: a risk amplifier, a sensitive program name, an MCP server name and exposure rule, a secret category, a missing or bypassed governance harness, or a paused transcript observer
* For each attack pattern finding: the detector that raised it, its identifier (a hash), its severity, the detector's description, the name of the process and of its parent process, the destination domain name (or, when there is none, the destination IP address) and port, the detection basis, the framework reference, whether you dismissed it on this device, and whether an AI model reviewed it. The description can contain full file and program paths, which often include your user account name, and, when an AI agent re-ran a denied command under another spelling, both commands
* For each behavioral divergence finding: its category, identifier, severity, description, the process name, the agent concerned, what triggered it, and the number of unexpected sensitive files (not their paths)
* For each Assistant action waiting for your review: its identifier, its type and its priority
* Whether the attack pattern detector, the divergence engine or the Assistant is switched off

Agent transcripts, prompts, model responses, file contents, environment variable values and secret values are never reported.

The administrators of the domain you are connected to see these details next to your score in EDAMAME Hub. This information is used solely by EDAMAME and is not shared with any third party.

You can turn this setting off at any time in Config > Privacy or in Trust > Connect: the next score report no longer carries these details. An organization that manages this device can also turn this sharing on for it.

If you do not agree with this policy, leave this setting off.
