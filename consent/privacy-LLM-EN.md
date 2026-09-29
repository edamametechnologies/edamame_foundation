EDAMAME Portal AI Service Privacy Policy (EN)
=============================================

By connecting to the EDAMAME Portal AI service, you agree to the processing described below.

**Connecting turns protection on**

Agreeing turns on EDAMAME's agentic protection. It stays on until you turn it off with the protection button on the Security screen.
* On a computer, protection runs the Assistant, attack pattern detection and behavioral divergence detection, and starts the two monitors they read:
  * Session capture, which records the metadata of this computer's network connections: source and destination IP addresses, ports, domain names, byte and packet counts, timing, and the program that opened each connection (its name, path, command line, working directory, user account and open files). Packet contents are not recorded.
  * The file monitor, which records file creations, changes and deletions, with their paths.
* On a phone or tablet, protection runs the Assistant only.

These monitors keep their records on this device. Of what they record, only the information listed below is sent to the EDAMAME Portal AI service. Features you turn on separately, such as AI details in EDAMAME Hub score reports or notification channels, send data under their own settings and policies.

**What is sent to the EDAMAME AI service**

While you are connected, EDAMAME sends text prompts built from its findings on this device. Depending on what protection finds, a prompt can contain:
* For attack pattern findings: the detector's description of the finding (which can include file paths and, when an AI agent re-ran a denied command under another spelling, both commands), the process name and path, the parent process name and path and the parent script path, the destination domain name, IP address and port, the paths of the files the process had open, and the evidence the detector used (which checks matched, blocklist names, code-signing identifiers, detected AI agent governance harnesses)
* For behavioral divergence findings: the same process and file path details, the destination (domain name or IP address, and port), and the type of the AI agent involved with an identifier of its instance
* To build the behavioral model of an AI coding agent (Cursor, Claude Code, Codex and others): excerpts of that agent's recent transcripts, up to 3,000 characters each of your prompts and of the agent's replies, the session titles, the commands the agent ran, the files and URLs its tools touched, the path of the transcript file, and the agent's type and instance identifier
* For the Assistant's analysis of your security to-dos:
  * Network connections: source and destination IP addresses and ports, domain names, network operator (ASN) and country, and the program behind the connection (name, path, command line, working directory, user account, open files and parent program)
  * Devices on your local network: host name, type, vendor, operating system, the services they announce, open ports and the service banners they return. When a device has no other identifying information, its IP address, host name or MAC address is sent instead
  * Threat and policy names and descriptions, and data breach names and descriptions. In some cases the email address a breach was found for is included
  * With each to-do analysis, a summary of all your current security to-dos, which can repeat the details above
* When you ask for a coaching insight: scores and counts describing your use of AI coding agents and their security (for example the number of unmonitored agents and of active findings), and the names of their skills, hooks and workspaces. A workspace name is derived from its folder path and can include your account name

File paths often include your account name, for example `/Users/<name>/...` or `C:\Users\<name>\...`. What EDAMAME removes from prompts depends on its version:
* Up to EDAMAME 2.0.2, file paths are sent as recorded, the agent instance identifier includes this computer's host name, the user account of a network connection is sent by name, and transcript text is sent as written. It can contain anything that you or the agent typed, including secrets
* From EDAMAME 2.0.3, every prompt listed above except coaching insights writes the home folder part of a path as `~`, for example `~/.ssh/id_ed25519`; the rest of the path is sent as recorded, and your account name can still appear in part in a project folder name that an AI agent derived from a home folder whose name contains a dash or a dot. The agent instance identifier is replaced by a pseudonym that contains no host name and changes each time EDAMAME restarts. The user account of a network connection is sent by name only for system and service accounts, such as `root` or `SYSTEM`; any other account is sent as `user`. In transcript text, commands and the targets of tool calls, EDAMAME masks the secrets it recognizes before sending them: private keys, access tokens and API keys in the formats it knows, passwords in web addresses, and values written after a name such as `password`, `token` or `api_key`. The rest is sent as written and can still contain personal information, or a secret in a form EDAMAME does not recognize

EDAMAME also sends a notification record to your EDAMAME Portal account when protection raises an alert or the Assistant acts. The record contains this computer's host name, its public IP addresses, model and operating system version, the finding details listed above with file paths as recorded (they are not shortened to `~`) and, for divergence findings, the agent instance identifier, which includes this computer's host name, the model's reasoning, the actions taken and, for the Assistant's reports, your security score. Attack pattern and divergence findings are also added to your Portal finding history, with the same details.

**Identifiers sent to EDAMAME**
* With every request: this device's EDAMAME device identifier, and either the sign-in token of your EDAMAME account (you sign in with your email address, and the token identifies your account) or your EDAMAME API key
* When the app checks your Portal plan: this computer's host name and the type of its operating system. Unless you renamed the device in the Portal, the host name becomes its name in your Portal account

**How EDAMAME processes and keeps this data**
* Prompts are analyzed by Microsoft Azure OpenAI Service, on EDAMAME's behalf. Your account and device identifiers are not forwarded to it
* EDAMAME stores each prompt and its answer, with your account and device identifiers, so that a repeated request from your account is not analyzed twice. These entries are set to expire 12 hours after they are written
* Notification records are set to expire 1 day after they are sent. A Portal finding history entry is set to expire 90 days after this device last reported the same findings
* EDAMAME records token usage per account and device to apply your plan's limits. It also reviews usage in internal reports that name accounts by email address. On the free plan, once your account has used 80% of its monthly tokens, EDAMAME gives your email address to its email outreach provider, Apollo.io, to send you discount offers
* EDAMAME's service logs record your account and device identifiers and token counts, and the full text of each prompt that is sent for analysis (a prompt answered from the stored entries above is not logged again). No expiry is configured for these logs

**Your choices**
* Turn protection off at any time with the protection button on the Security screen. The Assistant, the detectors, session capture and the file monitor all stop, and EDAMAME no longer sends prompts on its own. While you stay connected, a prompt is still sent when an analysis is requested explicitly, from the app or by an AI agent through EDAMAME's MCP server
* Disconnect from the EDAMAME Portal in Config > AI to stop all use of the service. Your sign-in tokens are stored on this device and are removed when you disconnect
* Instead of the EDAMAME Portal, you can use your own model provider in Config > AI. The prompts are then sent directly to that provider

For more information about EDAMAME's general privacy practices, see our [Privacy Policy](https://www.edamame.tech/privacy).

If you do not agree with this policy, do not connect to the EDAMAME Portal AI service.
