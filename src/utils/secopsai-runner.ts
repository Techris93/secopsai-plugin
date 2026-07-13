import { execFileSync } from "child_process";
import { resolve, join } from "path";
import { homedir } from "os";

export interface SecOpsAIConfig {
  secopsaiPath?: string;
  edgePath?: string;
  socDbPath?: string;
  sessionDir?: string;
}

export const FINDING_ID_PATTERN = "^(OCF|SCM|EDGE|EXFIL|POLICY|MALWARE|PRIVESC)-[A-Z0-9-]+$";

export function resolvePath(inputPath: string): string {
  if (inputPath.startsWith("~")) {
    return resolve(homedir(), inputPath.slice(2));
  }
  return resolve(inputPath);
}

function secopsExecutable(secopsPath: string): string {
  const fullPath = resolvePath(secopsPath);
  return join(fullPath, ".venv", "bin", "secopsai");
}

function pythonExecutable(secopsPath: string): string {
  const fullPath = resolvePath(secopsPath);
  return join(fullPath, ".venv", "bin", "python");
}

export function runSecOpsAI(secopsPath: string, args: string[]): any {
  const result = execFileSync(secopsExecutable(secopsPath), [...args, "--json"], {
    encoding: "utf-8",
    cwd: resolvePath(secopsPath),
  });
  return JSON.parse(result);
}

export function runPythonScript(secopsPath: string, args: string[]): any {
  const result = execFileSync(pythonExecutable(secopsPath), args, {
    encoding: "utf-8",
    cwd: resolvePath(secopsPath),
  });
  try {
    return JSON.parse(result);
  } catch {
    return { output: result.trim() };
  }
}

export function runEdgeScript(edgePath: string, args: string[]): string {
  const fullPath = resolvePath(edgePath);
  return execFileSync(join(fullPath, "scripts", "edge"), args, {
    encoding: "utf-8",
    cwd: fullPath,
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  }).trim();
}
