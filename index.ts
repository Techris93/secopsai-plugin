import { definePluginEntry, type PluginAPI } from "./src/types/openclaw-sdk.js";
import { Type } from "@sinclair/typebox";
import {
  FINDING_ID_PATTERN,
  runSecOpsAI,
  resolvePath,
  type SecOpsAIConfig,
} from "./src/utils/secopsai-runner.js";

const findingIdField = Type.String({
  pattern: FINDING_ID_PATTERN,
  description: "Finding ID such as EDGE-..., SCM-..., OCF-..., EXFIL-..., or POLICY-...",
});

export default definePluginEntry({
  id: "secopsai",
  name: "SecOpsAI",
  description: "Native SecOpsAI findings, source-backed triage, session approvals, orchestration, and supply-chain investigation tools.",

  register(api: PluginAPI) {
    const config = api.config as SecOpsAIConfig;
    const secopsPath = config.secopsaiPath || "~/secopsai";
    const sessionIdField = Type.String({
      pattern: "^SES-[0-9a-f]{12}$",
      description: "Session ID such as SES-3f6a12bc45de",
    });
    const approvalIdField = Type.String({
      pattern: "^APR-[0-9a-f]{12}$",
      description: "Approval ID such as APR-3f6a12bc45de",
    });

    function withDbPath(args: string[]): string[] {
      if (config.socDbPath) args.push("--db-path", resolvePath(config.socDbPath));
      return args;
    }

    function withSessionDir(args: string[]): string[] {
      if (config.sessionDir) args.push("--session-dir", resolvePath(config.sessionDir));
      return args;
    }

    api.registerTool({
      name: "secopsai_list_findings",
      description: "List findings from the local SecOpsAI SOC store by status, severity, or limit.",
      parameters: Type.Object({
        status: Type.Optional(Type.String({
          enum: ["open", "in_review", "closed"],
          description: "Filter findings by status",
        })),
        severity: Type.Optional(Type.String({
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Filter findings by severity",
        })),
        limit: Type.Optional(Type.Number({
          default: 20,
          description: "Maximum number of findings to return",
        })),
      }),
      async execute(_id, params) {
        const args = withDbPath(["triage", "list"]);
        if (params.status) args.push("--status", params.status);
        if (params.severity) args.push("--severity", params.severity);
        args.push("--limit", String(params.limit || 20));
        const result = runSecOpsAI(secopsPath, args);
        const findings = Array.isArray(result.findings) ? result.findings : [];
        const lines = findings.map((finding: any) =>
          `- ${finding.finding_id} | ${finding.severity} | status=${finding.status} | disposition=${finding.disposition} | ${finding.title}`
        );
        return {
          content: [{
            type: "text",
            text: lines.length ? lines.join("\n") : "No findings matched the query.",
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_edge_assets",
      description: "List network assets imported from SecOpsAI Edge into the local Core asset graph.",
      parameters: Type.Object({
        limit: Type.Optional(Type.Number({
          default: 50,
          minimum: 1,
          maximum: 500,
          description: "Maximum Edge assets to return",
        })),
      }),
      async execute(_id, params) {
        const args = withDbPath(["graph", "assets", "--limit", String(params.limit || 50)]);
        const result = runSecOpsAI(secopsPath, args);
        const assets = Array.isArray(result.assets) ? result.assets : [];
        const lines = assets.map((asset: any) =>
          `- ${asset.ip_address || "unknown-ip"} | status=${asset.status || "unknown"} | vendor=${asset.vendor || "unknown"} | host=${asset.hostname || "unknown"}`
        );
        return {
          content: [{
            type: "text",
            text: lines.length ? lines.join("\n") : "No SecOpsAI Edge assets are present in the Core graph.",
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_edge_changes",
      description: "Show recently changed Edge graph nodes and relationships from the local Core store.",
      parameters: Type.Object({
        limit: Type.Optional(Type.Number({
          default: 25,
          minimum: 1,
          maximum: 200,
          description: "Maximum recent graph changes to return",
        })),
      }),
      async execute(_id, params) {
        const args = withDbPath(["graph", "changes", "--limit", String(params.limit || 25)]);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_edge_sync_status",
      description: "Show recent Edge-to-Core sync freshness and contract metadata from the local Core store.",
      parameters: Type.Object({
        limit: Type.Optional(Type.Number({
          default: 20,
          minimum: 1,
          maximum: 500,
          description: "Maximum sync records to return",
        })),
      }),
      async execute(_id, params) {
        const args = withDbPath(["edge", "status", "--limit", String(params.limit || 20)]);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_edge_findings",
      description: "List SecOpsAI Edge-origin findings from the canonical local Core triage store.",
      parameters: Type.Object({
        status: Type.Optional(Type.String({
          enum: ["open", "in_review", "closed"],
          description: "Filter Edge findings by Core triage status",
        })),
        limit: Type.Optional(Type.Number({
          default: 20,
          minimum: 1,
          maximum: 200,
          description: "Maximum Edge findings to return",
        })),
      }),
      async execute(_id, params) {
        const args = withDbPath(["triage", "list", "--source", "secopsai_edge"]);
        if (params.status) args.push("--status", params.status);
        args.push("--limit", String(params.limit || 20));
        const result = runSecOpsAI(secopsPath, args);
        const findings = Array.isArray(result.findings) ? result.findings : [];
        const lines = findings.map((finding: any) =>
          `- ${finding.finding_id} | ${finding.severity} | status=${finding.status} | ${finding.title}`
        );
        return {
          content: [{
            type: "text",
            text: lines.length ? lines.join("\n") : "No SecOpsAI Edge findings matched the query.",
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_investigate_finding",
      description: "Run native triage investigation for a finding and return the structured result, optionally reusing or creating a SecOpsAI session.",
      parameters: Type.Object({
        findingId: findingIdField,
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
        sessionId: Type.Optional(sessionIdField),
        openSession: Type.Optional(Type.Boolean({
          default: true,
          description: "Create a triage session automatically when sessionId is not supplied",
        })),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const args = withSessionDir(withDbPath([
          "triage",
          "investigate",
          params.findingId,
          "--search-root",
          searchRoot,
        ]));
        if (params.sessionId) {
          args.push("--session-id", params.sessionId);
        } else if (params.openSession !== false) {
          args.push("--open-session");
        }
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_investigate_with_sources",
      description: "Run native triage investigation with an attached source-backed research report for the finding.",
      parameters: Type.Object({
        findingId: findingIdField,
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
        sessionId: Type.Optional(sessionIdField),
        openSession: Type.Optional(Type.Boolean({
          default: true,
          description: "Create a triage session automatically when sessionId is not supplied",
        })),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const args = withSessionDir(withDbPath([
          "triage",
          "investigate",
          params.findingId,
          "--search-root",
          searchRoot,
          "--with-research",
        ]));
        if (params.sessionId) {
          args.push("--session-id", params.sessionId);
        } else if (params.openSession !== false) {
          args.push("--open-session");
        }
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_research_finding",
      description: "Generate a source-backed research report for one finding, optionally attaching it to a session.",
      parameters: Type.Object({
        findingId: findingIdField,
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
        sessionId: Type.Optional(sessionIdField),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const args = withSessionDir(withDbPath([
          "research",
          "finding",
          params.findingId,
          "--search-root",
          searchRoot,
        ]));
        if (params.sessionId) args.push("--session-id", params.sessionId);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_research_package",
      description: "Generate a source-backed package research report using SecOpsAI's supply-chain and local-reference evidence.",
      parameters: Type.Object({
        ecosystem: Type.String({
          enum: ["pypi", "npm"],
          description: "Package ecosystem",
        }),
        packageName: Type.String({
          description: "Package name",
        }),
        version: Type.Optional(Type.String({
          description: "Optional version hint",
        })),
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
        sessionId: Type.Optional(sessionIdField),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const args = withSessionDir([
          "research",
          "package",
          "--ecosystem",
          params.ecosystem,
          "--package",
          params.packageName,
          "--search-root",
          searchRoot,
        ]);
        if (params.version) args.push("--version", params.version);
        if (params.sessionId) args.push("--session-id", params.sessionId);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_review_release_with_sources",
      description: "Review one package release with source-backed evidence. This is a release-review alias for package research.",
      parameters: Type.Object({
        ecosystem: Type.String({
          enum: ["pypi", "npm"],
          description: "Package ecosystem",
        }),
        packageName: Type.String({
          description: "Package name",
        }),
        version: Type.Optional(Type.String({
          description: "Optional version hint",
        })),
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
        sessionId: Type.Optional(sessionIdField),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const args = withSessionDir([
          "research",
          "package",
          "--ecosystem",
          params.ecosystem,
          "--package",
          params.packageName,
          "--search-root",
          searchRoot,
        ]);
        if (params.version) args.push("--version", params.version);
        if (params.sessionId) args.push("--session-id", params.sessionId);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_close_finding",
      description: "Request approval to close a finding. This tool no longer writes directly; resolve the returned approval to apply it.",
      parameters: Type.Object({
        findingId: findingIdField,
        disposition: Type.String({
          enum: [
            "true_positive",
            "false_positive",
            "expected_behavior",
            "accepted_risk",
            "exception_granted",
            "needs_review",
            "tune_policy",
          ],
          description: "Final analyst disposition",
        }),
        note: Type.String({
          description: "Analyst note explaining why the finding is being closed",
        }),
        status: Type.Optional(Type.String({
          enum: ["triaged", "closed"],
          default: "closed",
          description: "Target finding status if approved",
        })),
        sessionId: sessionIdField,
      }),
      async execute(_id, params) {
        const args = withSessionDir(withDbPath([
          "session",
          "request-approval",
          params.sessionId,
          "--type",
          "triage_close",
          "--finding-id",
          params.findingId,
          "--disposition",
          params.disposition,
          "--note",
          params.note,
          "--status",
          params.status || "closed",
        ]));
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    }, { optional: true });

    api.registerTool({
      name: "secopsai_supply_chain_suggest_fp_action",
      description: "Suggest the most practical false-positive action for a supply-chain finding.",
      parameters: Type.Object({
        findingId: findingIdField,
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const result = runSecOpsAI(secopsPath, [
          "supply-chain",
          "suggest-fp-action",
          params.findingId,
          "--search-root",
          searchRoot,
        ]);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_triage_orchestrate",
      description: "Run the native SecOpsAI triage orchestrator with auto-apply disabled so resulting actions still require approval.",
      parameters: Type.Object({
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
        limit: Type.Optional(Type.Number({
          default: 20,
          description: "Maximum number of findings to process",
        })),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const args = withDbPath([
          "triage",
          "orchestrate",
          "--search-root",
          searchRoot,
          "--limit",
          String(params.limit || 20),
          "--no-auto-apply-safe",
        ]);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    }, { optional: true });

    api.registerTool({
      name: "secopsai_triage_queue",
      description: "Show pending triage actions that still require analyst approval.",
      parameters: Type.Object({}),
      async execute() {
        const result = runSecOpsAI(secopsPath, ["triage", "queue"]);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_triage_apply_action",
      description: "Request approval to apply a queued triage action. This tool no longer applies directly; resolve the returned approval to apply it.",
      parameters: Type.Object({
        actionId: Type.String({
          pattern: "^ACT-[0-9]+$",
          description: "Queued action ID such as ACT-0001",
        }),
        sessionId: sessionIdField,
        summary: Type.Optional(Type.String({
          description: "Optional human-readable approval summary",
        })),
      }),
      async execute(_id, params) {
        const args = withSessionDir(withDbPath([
          "session",
          "request-approval",
          params.sessionId,
          "--type",
          "triage_action",
          "--action-id",
          params.actionId,
        ]));
        if (params.summary) args.push("--summary", params.summary);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    }, { optional: true });

    api.registerTool({
      name: "secopsai_triage_summary",
      description: "Summarize current orchestrator state, queue counts, and report locations.",
      parameters: Type.Object({}),
      async execute() {
        const result = runSecOpsAI(secopsPath, withDbPath(["triage", "summary"]));
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_session_list",
      description: "List recent SecOpsAI investigation sessions, optionally filtered by status or finding.",
      parameters: Type.Object({
        status: Type.Optional(Type.String({
          enum: ["open", "closed"],
          description: "Filter sessions by status",
        })),
        findingId: Type.Optional(findingIdField),
        limit: Type.Optional(Type.Number({
          default: 20,
          description: "Maximum number of sessions to return",
        })),
      }),
      async execute(_id, params) {
        const args = withSessionDir(["session", "list"]);
        if (params.status) args.push("--status", params.status);
        if (params.findingId) args.push("--finding-id", params.findingId);
        args.push("--limit", String(params.limit || 20));
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_session_show",
      description: "Show one SecOpsAI investigation session, including plan steps, approvals, and artifacts.",
      parameters: Type.Object({
        sessionId: sessionIdField,
      }),
      async execute(_id, params) {
        const result = runSecOpsAI(secopsPath, withSessionDir(["session", "show", params.sessionId]));
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    api.registerTool({
      name: "secopsai_session_request_close_approval",
      description: "Request an approval inside a session for a guarded finding close/disposition decision.",
      parameters: Type.Object({
        sessionId: sessionIdField,
        findingId: findingIdField,
        disposition: Type.String({
          enum: [
            "true_positive",
            "false_positive",
            "expected_behavior",
            "accepted_risk",
            "exception_granted",
            "needs_review",
            "tune_policy",
          ],
          description: "Disposition to request approval for",
        }),
        note: Type.String({
          description: "Analyst note / rationale for the approval request",
        }),
        status: Type.Optional(Type.String({
          enum: ["triaged", "closed"],
          default: "closed",
          description: "Target finding status if approved",
        })),
        summary: Type.Optional(Type.String({
          description: "Optional human-readable approval summary",
        })),
      }),
      async execute(_id, params) {
        const args = withSessionDir(withDbPath([
          "session",
          "request-approval",
          params.sessionId,
          "--type",
          "triage_close",
          "--finding-id",
          params.findingId,
          "--disposition",
          params.disposition,
          "--note",
          params.note,
          "--status",
          params.status || "closed",
        ]));
        if (params.summary) args.push("--summary", params.summary);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    }, { optional: true });

    api.registerTool({
      name: "secopsai_session_request_action_approval",
      description: "Request an approval inside a session before applying a queued triage action.",
      parameters: Type.Object({
        sessionId: sessionIdField,
        actionId: Type.String({
          pattern: "^ACT-[0-9]+$",
          description: "Queued action ID such as ACT-0001",
        }),
        summary: Type.Optional(Type.String({
          description: "Optional human-readable approval summary",
        })),
      }),
      async execute(_id, params) {
        const args = withSessionDir(withDbPath([
          "session",
          "request-approval",
          params.sessionId,
          "--type",
          "triage_action",
          "--action-id",
          params.actionId,
        ]));
        if (params.summary) args.push("--summary", params.summary);
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    }, { optional: true });

    api.registerTool({
      name: "secopsai_session_resolve_approval",
      description: "Approve or reject a pending session approval, optionally applying the approved change immediately.",
      parameters: Type.Object({
        sessionId: sessionIdField,
        approvalId: approvalIdField,
        decision: Type.String({
          enum: ["approved", "rejected"],
          description: "Final approval decision",
        }),
        apply: Type.Optional(Type.Boolean({
          default: true,
          description: "Apply the approved change immediately when decision is approved",
        })),
        note: Type.Optional(Type.String({
          description: "Optional approval decision note",
        })),
        decidedBy: Type.Optional(Type.String({
          description: "Optional analyst or approver identifier",
        })),
      }),
      async execute(_id, params) {
        const args = withSessionDir(withDbPath([
          "session",
          "resolve-approval",
          params.sessionId,
          params.approvalId,
          params.decision === "approved" ? "--approve" : "--reject",
        ]));
        if (params.note) args.push("--note", params.note);
        if (params.decidedBy) args.push("--decided-by", params.decidedBy);
        if (params.apply !== false && params.decision === "approved") args.push("--apply");
        const result = runSecOpsAI(secopsPath, args);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });
  },
});
