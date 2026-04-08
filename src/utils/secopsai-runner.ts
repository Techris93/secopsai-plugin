import { execSync } from "child_process";
import { resolve } from "path";
import { homedir } from "os";

export interface SecOpsAIConfig {
  secopsaiPath?: string;
  socDbPath?: string;
}

export const FINDING_ID_PATTERN = "^(OCF|SCM|EXFIL|POLICY|MALWARE|PRIVESC)-[A-Z0-9-]+$";

export function resolvePath(inputPath: string): string {
  if (inputPath.startsWith("~")) {
    return resolve(homedir(), inputPath.slice(2));
  }
  return resolve(inputPath);
}

export function runSecOpsAI(secopsPath: string, command: string): any {
  const fullPath = resolvePath(secopsPath);
  const cmd = `cd "${fullPath}" && source .venv/bin/activate && secopsai ${command} --json`;
  const result = execSync(cmd, { encoding: "utf-8", shell: "/bin/bash" });
  return JSON.parse(result);
}

export function runPythonScript(secopsPath: string, scriptCommand: string): any {
  const fullPath = resolvePath(secopsPath);
  const cmd = `cd "${fullPath}" && source .venv/bin/activate && python ${scriptCommand}`;
  const result = execSync(cmd, { encoding: "utf-8", shell: "/bin/bash" });
  try {
    return JSON.parse(result);
  } catch {
    return { output: result.trim() };
  }
}
