import { definePluginEntry, type PluginAPI } from "./src/types/openclaw-sdk.js";
import { Type } from "@sinclair/typebox";
import { runSecOpsAI, runPythonScript, resolvePath, type SecOpsAIConfig } from "./src/utils/secopsai-runner.js";

export default definePluginEntry({
  id: "secopsai",
  name: "SecOpsAI",
  description: "Conversational SecOps for OpenClaw audit logs",

  register(api: PluginAPI) {
    const config = api.config as SecOpsAIConfig;
    const secopsPath = config.secopsaiPath || "~/secopsai";

    // Tool: List findings
    api.registerTool({
      name: "secopsai_list_findings",
      description: "List SecOps findings with optional severity filter",
      parameters: Type.Object({
        severity: Type.Optional(Type.String({ 
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Filter findings by severity level"
        })),
        cacheTtl: Type.Optional(Type.Number({ 
          default: 60,
          description: "Cache time-to-live in seconds"
        }))
      }),
      async execute(_id, params) {
        const severityFlag = params.severity ? `--severity ${params.severity}` : "";
        const cacheFlag = `--cache-ttl ${params.cacheTtl || 60}`;
        const result = runSecOpsAI(secopsPath, `list ${severityFlag} ${cacheFlag}`.trim());
        
        const findings = result.findings || [];
        const highCount = findings.filter((f: any) => f.severity === "HIGH").length;
        const criticalCount = findings.filter((f: any) => f.severity === "CRITICAL").length;
        
        const highSeverityFindings = findings
          .filter((f: any) => ["HIGH", "CRITICAL"].includes(f.severity))
          .map((f: any) => `- ${f.finding_id}: ${f.title} (${f.severity})`)
          .join("\n");
        
        return {
          content: [{
            type: "text",
            text: `Found ${findings.length} findings (${criticalCount} critical, ${highCount} high)\n\n${highSeverityFindings || "No high/critical findings."}`
          }]
        };
      }
    });

    // Tool: Refresh pipeline
    api.registerTool({
      name: "secopsai_refresh",
      description: "Run the SecOpsAI detection pipeline to refresh findings",
      parameters: Type.Object({}),
      async execute() {
        const result = runSecOpsAI(secopsPath, "refresh");
        return {
          content: [{
            type: "text",
            text: `Pipeline refreshed. ${result.findings_created || 0} new findings created.`
          }]
        };
      }
    });

    // Tool: Show finding details
    api.registerTool({
      name: "secopsai_show_finding",
      description: "Get detailed information about a specific finding",
      parameters: Type.Object({
        findingId: Type.String({ 
          pattern: "^OCF-[A-F0-9]+$",
          description: "The finding ID (e.g., OCF-A1B2C3D4)"
        })
      }),
      async execute(_id, params) {
        const result = runSecOpsAI(secopsPath, `show ${params.findingId}`);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2)
          }]
        };
      }
    });

    // Tool: Triage finding (WRITE - mark as optional for safety)
    api.registerTool(
      {
        name: "secopsai_triage",
        description: "Triage a finding: set disposition, status, and add note",
        parameters: Type.Object({
          findingId: Type.String({ 
            pattern: "^OCF-[A-F0-9]+$",
            description: "The finding ID to triage"
          }),
          disposition: Type.String({ 
            enum: ["true_positive", "false_positive", "benign"],
            description: "Classification of the finding"
          }),
          status: Type.String({ 
            enum: ["open", "triaged", "closed"],
            description: "New status for the finding"
          }),
          note: Type.Optional(Type.String({
            description: "Optional analyst note"
          }))
        }),
        async execute(_id, params) {
          const { findingId, disposition, status, note } = params;
          
          // Run triage commands
          runPythonScript(secopsPath, `soc_store.py set-disposition ${findingId} ${disposition}`);
          runPythonScript(secopsPath, `soc_store.py set-status ${findingId} ${status}`);
          if (note) {
            runPythonScript(secopsPath, `soc_store.py add-note ${findingId} analyst "${note}"`);
          }
          
          return {
            content: [{
              type: "text",
              text: `Triage complete: ${findingId} → disposition=${disposition}, status=${status}`
            }]
          };
        }
      },
      { optional: true } // Requires user opt-in
    );

    // Tool: Check for threats
    api.registerTool({
      name: "secopsai_check_threats",
      description: "Check for malware or exfiltration indicators",
      parameters: Type.Object({
        type: Type.String({ 
          enum: ["malware", "exfil", "both"],
          description: "Type of threat check to perform"
        }),
        severity: Type.Optional(Type.String({ 
          enum: ["info", "low", "medium", "high"],
          default: "medium",
          description: "Minimum severity threshold"
        }))
      }),
      async execute(_id, params) {
        const result = runSecOpsAI(secopsPath, `check --type ${params.type} --severity ${params.severity}`);
        return {
          content: [{
            type: "text",
            text: `${params.type} check: ${result.matched_count || 0} matches (${result.high_or_above || 0} high+)`
          }]
        };
      }
    });

    // Tool: Get mitigation steps
    api.registerTool({
      name: "secopsai_mitigate",
      description: "Get recommended mitigation steps for a finding",
      parameters: Type.Object({
        findingId: Type.String({ 
          pattern: "^OCF-[A-F0-9]+$",
          description: "The finding ID to get mitigation steps for"
        })
      }),
      async execute(_id: string, params: { findingId: string }) {
        const result = runSecOpsAI(secopsPath, `mitigate ${params.findingId} --cache-ttl 60`);
        const actions = result.recommended_actions || [];
        
        const mitigationText = actions.length 
          ? `Mitigation steps for ${params.findingId}:\n\n${actions.map((a: string, i: number) => `${i + 1}. ${a}`).join("\n")}`
          : `No curated mitigation steps available for ${params.findingId}. Review associated events and restrict over-permissive skills.`;
        
        return {
          content: [{
            type: "text",
            text: mitigationText
          }]
        };
      }
    });

    // Tool: Search findings by keyword
    api.registerTool({
      name: "secopsai_search",
      description: "Search findings by keyword or pattern",
      parameters: Type.Object({
        query: Type.String({
          description: "Search query string"
        }),
        severity: Type.Optional(Type.String({ 
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Filter by severity"
        }))
      }),
      async execute(_id, params) {
        const severityFlag = params.severity ? `--severity ${params.severity}` : "";
        const result = runSecOpsAI(secopsPath, `search "${params.query}" ${severityFlag}`.trim());
        const findings = result.findings || [];
        
        return {
          content: [{
            type: "text",
            text: `Search results for "${params.query}": ${findings.length} findings\n\n` +
              findings.map((f: any) => `- ${f.finding_id}: ${f.title} (${f.severity})`).join("\n") || "No findings found."
          }]
        };
      }
    });

    // Tool: Get SOC database stats
    api.registerTool({
      name: "secopsai_stats",
      description: "Get statistics about the SOC database",
      parameters: Type.Object({}),
      async execute() {
        const dbPath = config.socDbPath || "~/secopsai/data/openclaw/findings/openclaw_soc.db";
        const resolvedDbPath = resolvePath(dbPath);
        
        // Query the database for stats
        const result = runPythonScript(
          secopsPath, 
          `-c "import sqlite3; conn=sqlite3.connect('${resolvedDbPath}'); cursor=conn.cursor(); cursor.execute('SELECT status, COUNT(*) FROM findings GROUP BY status'); print(cursor.fetchall()); conn.close()"`
        );
        
        return {
          content: [{
            type: "text",
            text: `SOC Database Stats:\n${JSON.stringify(result, null, 2)}`
          }]
        };
      }
    });
  }
});
