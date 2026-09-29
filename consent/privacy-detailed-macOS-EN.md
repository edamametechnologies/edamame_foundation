macOS Detailed Score Privacy Policy (EN)
========================================

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

**Who sees this information and how long EDAMAME Hub keeps it**
* The administrators of the domain you are connected to see this information in EDAMAME Hub, and EDAMAME staff can view it through EDAMAME's administration console
* If the domain's administrators connect EDAMAME Hub to other services, such as a compliance platform (Vanta), an access-control provider (for example Netskope) or a GitHub organization, EDAMAME Hub sends them this device's status and the details they need to recognize it, such as its IP addresses or its VPN or ZTNA peer IDs
* EDAMAME Hub keeps the latest report of this device with no expiry date. Each new report replaces it, and it is deleted when an administrator removes the device, when the domain is deleted, or 7 days after the last report of a device the domain has disabled
* EDAMAME Hub also keeps earlier reports for 7 days on a free domain plan and for 365 days on a paid plan, including after the device or the domain is deleted. They hold the device identifier, your username, the operating system type, the overall score and compliance, the status of each check, the public IP addresses and the approximate location
* EDAMAME's service logs record the reports EDAMAME Hub receives. No expiry is configured for these logs
* When you certify your score, EDAMAME emails the report to the address you enter and keeps that address. Unless it is an edamame.tech address, EDAMAME also gives it to its email outreach provider, Apollo.io, which can send you follow-up emails. EDAMAME's team is notified of each certification in its Slack workspace, with the device identifier, the username, the operating system, the score, the city and country, and the email address

Apart from the services named in this policy, EDAMAME does not share this information with third parties.

This information is gathered using a public "threat model": the checks it runs, with their scripts, are published at the links below.

The threat model can be seen at [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-macOS.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-macOS.json).

The threat model wiki can be seen at [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-macOS-EN](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-macOS-EN).

If you do not agree with this policy, please do not report your score.
