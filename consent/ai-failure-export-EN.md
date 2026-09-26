AI Failure Details Sharing Policy (EN)
======================================

This setting adds the details of failing AI agent security checks to the score reports this device sends to the domain it is connected to. It is off unless you turn it on, and your score reports work without it.

By turning it on, you agree to share the following information with EDAMAME in each score report:
* For every AI coding agent EDAMAME supports, whether it is installed on this machine and whether its transcript observer is running
* For each failing AI agent security check:
  * The name of the agent the failure belongs to, for example `cursor` or `claude_code`
  * The name of the governance harness that agent declares, for example `nono` or `srt`
  * The name of the risk amplifier that fired, for example `passwordless_root`, `critical_subprocess` or `secret_exposure`
  * The file name, without its path or its arguments, of a sensitive program the agent launched, for example `ssh`
  * The configured name of an MCP server found to be exposed, for example `gojiberry`, together with the exposure rule that fired, for example `mcp_public_no_strong_auth`. MCP servers that are not exposed are never named
  * The category of a secret found in the agent transcript, for example `aws_credentials`, never the secret itself

Agent transcripts, prompts, model responses, file contents, command arguments, environment variable values and secret values are never reported.

The administrators of the domain you are connected to see these details next to your score in EDAMAME Hub. This information is used solely by EDAMAME and is not shared with any third party.

You can turn this setting off at any time in Config > Privacy or in Trust > Connect: the next score report no longer carries these details. An organization that manages this device can also turn this sharing on for it.

If you do not agree with this policy, leave this setting off.
