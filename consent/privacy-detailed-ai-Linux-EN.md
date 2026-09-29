Linux Detailed Score Privacy Policy with AI Details (EN)
========================================================

By reporting a detailed score, you agree to share the following information with EDAMAME:
* Your machine unique identifier
* Your machine name (hostname), without its network domain suffix
* Your operating system name and version
* Your public IPv4 address and/or IPv6 address
* Your approximate location derived from your public IPv4 address: city, region, country, time zone, latitude and longitude. To find it, EDAMAME sends your public IPv4 address to the ip-api.com geolocation service
* Your MAC address if available
* Your peer IDs for your VPN or ZTNA connections if available
* The domain you are connected to, your username in that domain and the access code used to connect or, when you certify your score, the email address you enter
* The language of the EDAMAME interface
* The EDAMAME version, whether this machine is a CI/CD runner, and the state of the EDAMAME Helper
* The date and time of the report
* Your score as a single numerical value
* Your score for each category (network, system integrity, system services, applications, credentials), your star rating, and your compliance percentage for each compliance framework
* The history of the remediations and rollbacks you performed: the check concerned, the action, when it happened, and whether it succeeded and was validated
* Whether AI details sharing is on for this device. The AI details themselves are sent only when it is
* The name, date and signature of the threat model used, and for each of the following security checks: its definition as published in that threat model, its status (failing, passing or unknown) and when it was last evaluated:
  * EDAMAME helper inactive
  * No antivirus enabled
  * No password manager installed
  * Disk encryption disabled
  * Potentially compromised email address
  * Unverified or unsafe network environment
  * Unverified or unsafe services exposed to the LAN
  * Unverified or anomalous traffic
  * Unreviewed vulnerability findings
  * Behavioral divergence detected
  * Escalated actions pending review
  * File permissions /etc/passwd
  * File permissions /etc/shadow
  * File permissions /etc/fstab
  * File permissions /etc/group
  * Group Ownership of /etc/group
  * Group Ownership of /etc/shadow
  * Your OS is not up to date
  * Local firewall disabled
  * Remote login enabled
  * Remote desktop enabled
  * File sharing enabled
  * Screen saver requires password disabled
  * Secure boot disabled
  * Weak password policy
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

* The AI details of this machine:
  * AI setup of this machine, sent in every report while AI details are shared, even when no AI check is failing
    * The operating system family, and whether the assessed user account is an administrator, runs elevated or can become root without a password. The account name itself is not sent
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
    * For each attack pattern finding: the detector that raised it, its identifier (a hash), its severity, the file names, without paths, of the process and of its parent process, the destination and port, the detection basis, the framework reference, whether you dismissed it on this device, and whether an AI model reviewed it
      * The destination is the domain name or, when there is none, the IP address. A private, local-network or loopback destination is sent only as that category, for example `private network`, never as its address or name
      * For the files the finding touched: the category and the file name, without its folder, of each file EDAMAME's sensitive-file list recognizes, for example `ssh:id_ed25519`, and only the number of other files. A file in your home folder whose name contains your account name is sent as its category alone
      * When an AI agent re-ran a denied command under another spelling: the names of the programs involved, for example `curl`, without their arguments
    * For each behavioral divergence finding: its category, identifier, severity, the file name of the process, the agent concerned, the phrase the engine uses for what triggered it, for example `unexpected sensitive file access with unexplained external egress`, and the number of unexpected sensitive files (not their paths)
    * For each Assistant action waiting for your review: its identifier, its type and its priority
    * Whether the attack pattern detector, the divergence engine or the Assistant is switched off
    * The descriptions EDAMAME shows for these findings on this device are not sent: EDAMAME Hub shows a summary built from the items above

Agent transcripts, prompts, model responses, file contents, full file paths, command arguments, environment variable values and secret values are never reported.

**Who sees this information and how long EDAMAME Hub keeps it**
* The administrators of the domain you are connected to see this information in EDAMAME Hub, and EDAMAME staff can view it through EDAMAME's administration console
* If the domain's administrators connect EDAMAME Hub to other services, such as a compliance platform (Vanta), an access-control provider (for example Netskope) or a GitHub organization, EDAMAME Hub sends them this device's status and the details they need to recognize it, such as its IP addresses or its VPN or ZTNA peer IDs
* EDAMAME Hub keeps the latest report of this device with no expiry date. Each new report replaces it, and it is deleted when an administrator removes the device, when the domain is deleted, or 7 days after the last report of a device the domain has disabled
* EDAMAME Hub also keeps earlier reports for 7 days on a free domain plan and for 365 days on a paid plan, including after the device or the domain is deleted. They hold the device identifier, your username, the operating system type, the overall score and compliance, the status of each check, the public IP addresses and the approximate location
* EDAMAME's service logs record the reports EDAMAME Hub receives. No expiry is configured for these logs
* When you certify your score, EDAMAME emails the report to the address you enter and keeps that address. Unless it is an edamame.tech address, EDAMAME also gives it to its email outreach provider, Apollo.io, which can send you follow-up emails. EDAMAME's team is notified of each certification in its Slack workspace, with the device identifier, the username, the operating system, the score, the city and country, and the email address

Apart from the services named in this policy, EDAMAME does not share this information with third parties.

This information is gathered using a public "threat model": the checks it runs, with their scripts, are published at the links below.

The threat model can be seen at [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Linux.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Linux.json).

The threat model wiki can be seen at [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Linux-EN](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Linux-EN).

If you do not agree with this policy, please do not report your score.
