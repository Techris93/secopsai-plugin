// Stub types for OpenClaw Plugin SDK
// This is a placeholder until the official SDK is published

import { Static, TSchema } from "@sinclair/typebox";

export interface ToolContext {
  id: string;
}

export interface ToolParameters<T extends TSchema = TSchema> {
  [key: string]: unknown;
}

export interface ToolResult {
  content: Array<{
    type: "text" | "image" | "resource";
    text?: string;
    data?: unknown;
    mimeType?: string;
  }>;
  isError?: boolean;
}

export interface ToolDefinition<T extends TSchema = TSchema> {
  name: string;
  description: string;
  parameters: T;
  execute: (id: string, params: Static<T>) => Promise<ToolResult>;
}

export interface ToolOptions {
  optional?: boolean;
}

export interface PluginAPI {
  config: Record<string, unknown>;
  registerTool: <T extends TSchema>(
    definition: ToolDefinition<T>,
    options?: ToolOptions
  ) => void;
}

export interface PluginEntry {
  id: string;
  name: string;
  description: string;
  register: (api: PluginAPI) => void;
}

export function definePluginEntry(entry: PluginEntry): PluginEntry {
  return entry;
}
