import type { ReactNode } from "react";
import { Icon } from "./Icons";

type Tone = "ok" | "warn" | "serious" | "bad" | "info";
// Status always pairs a colour with an icon and a text label (never colour alone).
const TONE: Record<string, [Tone, string]> = {
  SUCCEEDED: ["ok", "checkCircle"], COMPLETED: ["ok", "checkCircle"], APPROVED: ["ok", "check"], approved: ["ok", "check"], executed: ["ok", "checkCircle"],
  FAILED: ["bad", "xCircle"], ABORTED: ["bad", "xCircle"], NEEDS_HUMAN: ["bad", "alert"], REJECTED: ["bad", "xCircle"], rejected: ["bad", "xCircle"],
  ROLLED_BACK: ["serious", "rotate"], ROLLING_BACK: ["serious", "rotate"], AWAITING_APPROVAL: ["warn", "clock"], pending_approval: ["warn", "clock"],
  EXPIRED: ["warn", "clock"], expired: ["warn", "clock"], aborted: ["bad", "xCircle"], executing: ["info", "play"],
  EXECUTING: ["info", "play"], VERIFYING: ["info", "play"], PRECHECKING: ["info", "play"], BACKING_UP: ["info", "play"],
  DIAGNOSING: ["info", "search"], ANALYZING: ["info", "search"], SUBMITTED: ["info", "dot"], CANCELLED: ["info", "x"],
  critical: ["bad", "xCircle"], high: ["serious", "alert"], medium: ["warn", "alert"], low: ["info", "dot"], info: ["info", "dot"],
  MUTATE: ["warn", "alert"], DESTRUCTIVE: ["bad", "alert"], READ: ["info", "dot"],
};
export const Badge = ({ value, label }: { value: string; label?: string }) => {
  const [tone, icon] = TONE[value] ?? ["info", "dot"];
  return <span className={`pill ${tone}`}><Icon name={icon} />{label ?? value.replace(/_/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase())}</span>;
};

export const Card = ({ title, sub, children, actions, className = "" }: { title?: string; sub?: string; children: ReactNode; actions?: ReactNode; className?: string }) => (
  <section className={`card ${className}`}>
    {(title || actions) && <header><h3>{title} {sub && <span className="sub">{sub}</span>}</h3>{actions}</header>}
    {children}
  </section>
);

export const PageHeader = ({ title, subtitle, actions, crumbs }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; crumbs?: ReactNode }) => (
  <div>
    {crumbs && <div className="crumbs">{crumbs}</div>}
    <div className="page-head"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{actions && <div className="row">{actions}</div>}</div>
  </div>
);

export const Empty = ({ icon = "inbox", children }: { icon?: string; children: ReactNode }) => (
  <div className="empty"><Icon name={icon} /><div>{children}</div></div>
);
export const Skeleton = ({ h = 16, w = "100%" }: { h?: number; w?: string | number }) => <div className="skeleton" style={{ height: h, width: w }} />;
export const ErrorMsg = ({ error }: { error: string | null }) => (error ? <p className="error" role="alert">{error}</p> : null);

const asDate = (s: string) => new Date(s.endsWith("Z") ? s : s + "Z");
export const fmt = (s: string | null) => (s ? asDate(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");
export const ago = (s: string) => {
  const sec = Math.max(0, (Date.now() - asDate(s).getTime()) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
};
