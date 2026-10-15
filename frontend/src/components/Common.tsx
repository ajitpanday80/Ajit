import type { ReactNode } from "react";

const TONE: Record<string, string> = {
  SUCCEEDED: "ok", COMPLETED: "ok", APPROVED: "ok", approved: "ok", executed: "ok",
  FAILED: "bad", ABORTED: "bad", NEEDS_HUMAN: "bad", REJECTED: "bad", rejected: "bad",
  ROLLED_BACK: "warn", ROLLING_BACK: "warn", AWAITING_APPROVAL: "warn", pending_approval: "warn", EXPIRED: "warn",
  critical: "bad", high: "bad", medium: "warn", low: "info", info: "info",
};
export const Badge = ({ value }: { value: string }) => <span className={`badge ${TONE[value] ?? "info"}`}>{value.replace(/_/g, " ")}</span>;
export const Card = ({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) => (
  <section className="card">{(title || actions) && <header><h3>{title}</h3>{actions}</header>}{children}</section>
);
export const ErrorMsg = ({ error }: { error: string | null }) => (error ? <p className="error" role="alert">{error}</p> : null);
export const fmt = (s: string | null) => (s ? new Date(s + (s.endsWith("Z") ? "" : "Z")).toLocaleString() : "—");
