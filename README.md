# OpenClaw SecOpsAI Plugin

Native SecOpsAI findings, triage orchestration, queued action handling, and supply-chain investigation for OpenClaw.

This release executes the local `secopsai` venv binary directly with structured argv arguments instead of shell-building command strings, reducing command-injection risk compared with the earlier release.

## Installation

```bash
# Install from ClawHub
openclaw plugins install clawhub:@techris93/secopsai

# Or install from local source
openclaw plugins install -l /path/to/openclaw-secopsai-plugin
```

## Configuration

Add to your OpenClaw configuration:

```json
{
  "plugins": {
    "entries": {
      "secopsai": {
        "enabled": true,
        "config": {
          "secopsaiPath": "~/secopsai",
          "socDbPath": "~/secopsai/data/openclaw/findings/openclaw_soc.db"
        }
      }
    }
  },
  "tools": {
    "allow": ["secopsai_triage"]
  }
}
```

## Tools

| Tool | Description | Safety |
|------|-------------|--------|
| `secopsai_list_findings` | List findings by status/severity | Read-only |
| `secopsai_investigate_finding` | Run native triage investigation for a finding | Read-only |
| `secopsai_close_finding` | Close a finding with disposition and analyst note | Write (optional) |
| `secopsai_supply_chain_suggest_fp_action` | Suggest the best false-positive action for an SCM finding | Read-only |
| `secopsai_triage_orchestrate` | Run the native triage orchestrator | Write (optional) |
| `secopsai_triage_queue` | Show queued actions awaiting analyst approval | Read-only |
| `secopsai_triage_apply_action` | Apply a queued triage action by ID | Write (optional) |
| `secopsai_triage_summary` | Show orchestrator summary and report paths | Read-only |

## Usage Examples

```
# List open findings
secopsai_list_findings status=open limit=20

# Investigate a supply-chain finding
secopsai_investigate_finding findingId=SCM-FA4BAE45589358A2

# Ask SecOpsAI what to do with a likely supply-chain false positive
secopsai_supply_chain_suggest_fp_action findingId=SCM-FA4BAE45589358A2

# Run the native orchestrator
secopsai_triage_orchestrate limit=20

# Review queued actions
secopsai_triage_queue

# Apply a queued action
secopsai_triage_apply_action actionId=ACT-0001

# Close a finding with an explicit analyst note
secopsai_close_finding findingId=SCM-FA4BAE45589358A2 disposition=expected_behavior note="Package not referenced locally."

# Show orchestrator summary
secopsai_triage_summary
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Link for local testing
openclaw plugins install -l $(pwd)

# Restart gateway
openclaw gateway restart
```

## Publishing

```bash
# Build before packaging
npm run build

# Create a tarball for ClawHub upload
npm pack
```

## License

MIT
