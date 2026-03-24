# OpenClaw SecOpsAI Plugin

Conversational SecOps for OpenClaw audit logs. Run detection pipelines, inspect findings, triage incidents, and get mitigation guidance.

## Installation

```bash
# Install from npm
openclaw plugins install @techris/openclaw-secopsai

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
| `secopsai_list_findings` | List SecOps findings with optional severity filter | Read-only |
| `secopsai_refresh` | Run the detection pipeline to refresh findings | Write |
| `secopsai_show_finding` | Get detailed information about a specific finding | Read-only |
| `secopsai_triage` | Triage a finding (set disposition, status, note) | Write (optional) |
| `secopsai_check_threats` | Check for malware or exfiltration indicators | Read-only |
| `secopsai_mitigate` | Get recommended mitigation steps for a finding | Read-only |
| `secopsai_search` | Search findings by keyword or pattern | Read-only |
| `secopsai_stats` | Get statistics about the SOC database | Read-only |

## Usage Examples

```
# List all critical findings
secopsai_list_findings severity=critical

# Refresh the detection pipeline
secopsai_refresh

# Show details of a specific finding
secopsai_show_finding findingId=OCF-A1B2C3D4

# Triage a finding as false positive
secopsai_triage findingId=OCF-A1B2C3D4 disposition=false_positive status=closed note=" benign misconfiguration"

# Check for exfiltration threats
secopsai_check_threats type=exfil severity=high

# Get mitigation steps
secopsai_mitigate findingId=OCF-A1B2C3D4

# Search findings by keyword
secopsai_search query="unauthorized" severity=high
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
# Build before publishing
npm run build

# Publish to npm
npm publish --access public
```

## License

MIT
