// Thin typed API client.  The JWT lives in sessionStorage (cleared when the tab closes) and is sent as a header.
export interface User { id: number; email: string; name: string; role: string; tenant_id: number; permissions?: string[] }
export interface Client { id: number; name: string; status: string; ai_policy: string; maintenance_enabled: boolean }
export interface Device { id: number; client_id: number; hostname: string; address: string; device_type: string; connector: string; status: string }
export interface Task {
  id: number; client_id: number; device_id: number; title: string; description: string; mode: "analysis_only" | "maintenance";
  state: string; source: string; created_at: string; completed_at: string | null; result: Record<string, unknown>;
  investigation?: Investigation | null; plans?: Plan[]; runs?: Run[];
}
export interface Finding { title: string; severity: string; detail: string; evidence_ids: number[]; source: string }
export interface Investigation { summary: string; root_cause: string; confidence: string; findings: Finding[]; recommendations: string[]; uncertainty: string[]; ai_used: string }
export interface PlanStep { idx: number; operation: string; params: Record<string, unknown>; risk: string; rationale: string; rollback_candidates: string[]; backup: string }
export interface Plan {
  id: number; task_id: number; version: number; steps: PlanStep[]; plan_hash: string; status: string; recovery_level: string; risk: string;
  requires_second_approver: boolean; requires_no_rollback_ack: boolean; rationale: string; expires_at: string;
  approvals?: { approver_id: number; decision: string; comment: string }[];
}
export interface Run {
  id: number; status: string; error: string | null; gate_results: Record<string, { ok: boolean; detail: string }>;
  state_diff: Record<string, { before: string; after: string; changed: boolean }>;
  steps: { step_idx: number; operation: string; status: string }[];
  verifications: { check: string; passed: boolean; detail: string }[];
  recovery_checks: { level: string; passed: boolean; detail: string }[];
  rollbacks: { status: string; state_restored: boolean; detail: string }[];
}
export interface TimelineEvent { seq: number; from_state: string | null; to_state: string; actor: string; at: string }
export interface Evidence { id: number; phase: string; operation: string; command_display: string; exit_code: number | null; output_sanitized: string; output_sha256: string; collected_at: string }

const KEY = "msp_token";
export const getToken = () => sessionStorage.getItem(KEY);
export const setToken = (t: string | null) => (t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY));

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined) };
  const t = getToken();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (init.json !== undefined) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(init.json); }
  const res = await fetch(`/api${path}`, { ...init, headers });
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) throw new ApiError(res.status, data?.error ?? res.statusText);
  return data as T;
}

/** Live timeline using fetch streaming so the bearer token is never placed in a URL. */
export async function streamTimeline(taskId: number, onEvent: (e: TimelineEvent) => void, signal: AbortSignal): Promise<void> {
  const res = await fetch(`/api/tasks/${taskId}/stream`, { headers: { Authorization: `Bearer ${getToken()}` }, signal });
  if (!res.ok || !res.body) return;
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    let i: number;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
      if (chunk.includes("event: end")) return;
      const m = chunk.match(/^data: (.*)$/m);
      if (m && chunk.includes("event: transition")) onEvent(JSON.parse(m[1]) as TimelineEvent);
    }
  }
}
