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
          "socDbPath": "~/secopsai/data/openclaw/findings/openclaw_soc.db",
          "sessionDir": "~/secopsai/data/sessions"
        }
      }
    }
  },
  "tools": {
    "allow": [
      "secopsai_close_finding",
      "secopsai_triage_orchestrate",
      "secopsai_triage_apply_action",
      "secopsai_session_request_close_approval",
      "secopsai_session_request_action_approval",
      "secopsai_session_resolve_approval"
    ]
  }
}
```

## Tools

| Tool | Description | Safety |
|------|-------------|--------|
| `secopsai_list_findings` | List findings by status/severity | Read-only |
| `secopsai_edge_assets` | List Edge-discovered assets imported into Core | Read-only |
| `secopsai_edge_changes` | Show recent Edge graph changes | Read-only |
| `secopsai_edge_sync_status` | Show Edge-to-Core sync freshness | Read-only |
| `secopsai_edge_findings` | List Edge-origin Core findings | Read-only |
| `secopsai_investigate_finding` | Run native triage investigation for a finding | Read-only |
| `secopsai_investigate_with_sources` | Investigate a finding and attach a source-backed research report | Read-only |
| `secopsai_research_finding` | Generate a source-backed report for a finding | Read-only |
| `secopsai_research_package` | Generate a source-backed package research report | Read-only |
| `secopsai_review_release_with_sources` | Review one package release with source-backed evidence | Read-only |
| `secopsai_close_finding` | Request approval to close a finding | Write approval request (optional) |
| `secopsai_session_list` | List recent SecOpsAI investigation sessions | Read-only |
| `secopsai_session_show` | Show one session with plan, approvals, and artifacts | Read-only |
| `secopsai_session_request_close_approval` | Request a guarded close/disposition approval in a session | Write (optional) |
| `secopsai_session_request_action_approval` | Request approval before applying a queued action | Write (optional) |
| `secopsai_session_resolve_approval` | Approve or reject a pending session approval | Write (optional) |
| `secopsai_supply_chain_suggest_fp_action` | Suggest the best false-positive action for an SCM finding | Read-only |
| `secopsai_triage_orchestrate` | Run the native triage orchestrator with auto-apply disabled | Write queue update (optional) |
| `secopsai_triage_queue` | Show queued actions awaiting analyst approval | Read-only |
| `secopsai_triage_apply_action` | Request approval to apply a queued action | Write approval request (optional) |
| `secopsai_triage_summary` | Show orchestrator summary and report paths | Read-only |

## Usage Examples

```
# List open findings
secopsai_list_findings status=open limit=20

# Review Edge assets and changes already synced into Core
secopsai_edge_assets limit=50
secopsai_edge_changes limit=25
secopsai_edge_sync_status limit=20
secopsai_edge_findings status=open limit=20

# Investigate a supply-chain finding
secopsai_investigate_finding findingId=SCM-FA4BAE45589358A2

# Investigate with attached source-backed research
secopsai_investigate_with_sources findingId=SCM-FA4BAE45589358A2

# Generate source-backed finding research only
secopsai_research_finding findingId=SCM-FA4BAE45589358A2

# Review a package release with source-backed evidence
secopsai_review_release_with_sources ecosystem=pypi packageName=litellm version=1.83.10

# List recent sessions
secopsai_session_list status=open limit=10

# Show one session
secopsai_session_show sessionId=SES-3f6a12bc45de

# Request approval for a guarded close decision
secopsai_session_request_close_approval sessionId=SES-3f6a12bc45de findingId=SCM-FA4BAE45589358A2 disposition=expected_behavior note="Package not referenced locally."

# Request approval before applying a queued action
secopsai_session_request_action_approval sessionId=SES-3f6a12bc45de actionId=ACT-0001 summary="Approve allowlist action for this package."

# Approve and apply a pending session approval
secopsai_session_resolve_approval sessionId=SES-3f6a12bc45de approvalId=APR-3f6a12bc45de decision=approved apply=true

# Ask SecOpsAI what to do with a likely supply-chain false positive
secopsai_supply_chain_suggest_fp_action findingId=SCM-FA4BAE45589358A2

# Run the native orchestrator
secopsai_triage_orchestrate limit=20

# Review queued actions
secopsai_triage_queue

# Request approval for a queued action
secopsai_triage_apply_action sessionId=SES-3f6a12bc45de actionId=ACT-0001

# Request approval to close a finding with an explicit analyst note
secopsai_close_finding sessionId=SES-3f6a12bc45de findingId=SCM-FA4BAE45589358A2 disposition=expected_behavior note="Package not referenced locally."

# Show orchestrator summary
secopsai_triage_summary
```

Write-facing tools request approvals or run with auto-apply disabled. Use `secopsai_session_resolve_approval decision=approved apply=true` to apply an approved close or queued action.

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
