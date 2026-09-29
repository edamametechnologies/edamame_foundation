AI Failure Details Sharing Policy (EN)
======================================

When this device is connected to a domain, it sends score reports to EDAMAME Hub. This setting adds AI details to those reports. It is off unless you turn it on, and your score reports work without it.

By turning it on, you agree to share the following information with EDAMAME in each score report.

**AI setup of this machine, sent in every report while AI details are shared, even when no AI check is failing**
* The operating system family, and whether the assessed user account is an administrator, runs elevated or can become root without a password. The account name itself is not sent
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
* For each attack pattern finding: the detector that raised it, its identifier (a hash), its severity, the file names, without paths, of the process and of its parent process, the destination and port, the detection basis, the framework reference, whether you dismissed it on this device, and whether an AI model reviewed it
  * The destination is the domain name or, when there is none, the IP address. A private, local-network or loopback destination is sent only as that category, for example `private network`, never as its address or name
  * For the files the finding touched: the category and the file name, without its folder, of each file EDAMAME's sensitive-file list recognizes, for example `ssh:id_ed25519`, and only the number of other files. A file in your home folder whose name contains your account name is sent as its category alone
  * When an AI agent re-ran a denied command under another spelling: the names of the programs involved, for example `curl`, without their arguments
* For each behavioral divergence finding: its category, identifier, severity, the file name of the process, the agent concerned, the phrase the engine uses for what triggered it, for example `unexpected sensitive file access with unexplained external egress`, and the number of unexpected sensitive files (not their paths)
* For each Assistant action waiting for your review: its identifier, its type and its priority
* Whether the attack pattern detector, the divergence engine or the Assistant is switched off
* The descriptions EDAMAME shows for these findings on this device are not sent: EDAMAME Hub shows a summary built from the items above

Agent transcripts, prompts, model responses, file contents, full file paths, command arguments, environment variable values and secret values are never reported.

The administrators of the domain you are connected to see these details next to your score in EDAMAME Hub, and EDAMAME staff can view them through EDAMAME's administration console. EDAMAME Hub also uses them to evaluate the domain's AI policies and access rules. They are not part of what EDAMAME Hub sends to other services the domain's administrators connect it to.

EDAMAME Hub keeps these details with the latest report of this device, with no expiry date. The next report that carries AI details replaces them, and they are deleted with that report: when an administrator removes the device, when the domain is deleted, or 7 days after the last report of a device the domain has disabled.

You can turn this setting off at any time in Config > Privacy or in Trust > Connect: the next score report no longer carries these details, and EDAMAME Hub discards the details it kept. An organization that manages this device can also turn this sharing on or off for it.

If you do not agree with this policy, leave this setting off.
