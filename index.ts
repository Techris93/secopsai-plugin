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
  description: "Finding ID such as SCM-..., OCF-..., EXFIL-..., or POLICY-...",
});

export default definePluginEntry({
  id: "secopsai",
  name: "SecOpsAI",
  description: "Native SecOpsAI findings, triage, orchestration, and supply-chain investigation tools.",

  register(api: PluginAPI) {
    const config = api.config as SecOpsAIConfig;
    const secopsPath = config.secopsaiPath || "~/secopsai";

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
        const flags = [
          params.status ? `--status ${params.status}` : "",
          params.severity ? `--severity ${params.severity}` : "",
          `--limit ${params.limit || 20}`,
        ].filter(Boolean).join(" ");
        const result = runSecOpsAI(secopsPath, `triage list ${flags}`.trim());
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
      name: "secopsai_investigate_finding",
      description: "Run native triage investigation for a finding and return the structured result.",
      parameters: Type.Object({
        findingId: findingIdField,
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const result = runSecOpsAI(
          secopsPath,
          `triage investigate ${params.findingId} --search-root "${searchRoot}"`
        );
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
      description: "Close a finding with an explicit disposition and analyst note.",
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
      }),
      async execute(_id, params) {
        const result = runSecOpsAI(
          secopsPath,
          `triage close ${params.findingId} --disposition ${params.disposition} --note "${params.note.replace(/"/g, '\\"')}"`
        );
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
        const result = runSecOpsAI(
          secopsPath,
          `supply-chain suggest-fp-action ${params.findingId} --search-root "${searchRoot}"`
        );
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
      description: "Run the native SecOpsAI triage orchestrator against open findings.",
      parameters: Type.Object({
        searchRoot: Type.Optional(Type.String({
          default: "~/secopsai",
          description: "Repository root used for dependency and local-reference checks",
        })),
        limit: Type.Optional(Type.Number({
          default: 20,
          description: "Maximum number of findings to process",
        })),
        autoApplySafe: Type.Optional(Type.Boolean({
          default: true,
          description: "Whether to auto-apply clearly safe actions",
        })),
      }),
      async execute(_id, params) {
        const searchRoot = resolvePath(params.searchRoot || secopsPath);
        const flags = [
          `--search-root "${searchRoot}"`,
          `--limit ${params.limit || 20}`,
          params.autoApplySafe === false ? "--no-auto-apply-safe" : "",
        ].filter(Boolean).join(" ");
        const result = runSecOpsAI(secopsPath, `triage orchestrate ${flags}`.trim());
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
        const result = runSecOpsAI(secopsPath, "triage queue");
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
      description: "Apply a queued triage action by action ID.",
      parameters: Type.Object({
        actionId: Type.String({
          pattern: "^ACT-[0-9]+$",
          description: "Queued action ID such as ACT-0001",
        }),
        yes: Type.Optional(Type.Boolean({
          default: true,
          description: "Apply without further confirmation",
        })),
      }),
      async execute(_id, params) {
        const flags = params.yes === false ? "" : "--yes";
        const result = runSecOpsAI(secopsPath, `triage apply-action ${params.actionId} ${flags}`.trim());
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
        const result = runSecOpsAI(secopsPath, "triage summary");
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
