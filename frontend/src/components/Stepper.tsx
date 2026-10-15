import { Icon } from "./Icons";

const STEPS: [string, string[]][] = [
  ["Diagnose", ["SUBMITTED", "DIAGNOSING"]], ["Analyze", ["ANALYZING"]], ["Approval", ["AWAITING_APPROVAL", "APPROVED", "EXPIRED"]],
  ["Backup & gates", ["PRECHECKING", "BACKING_UP"]], ["Execute", ["EXECUTING"]], ["Verify", ["VERIFYING"]],
];
const FAIL: Record<string, number> = { REJECTED: 2, ABORTED: 3, ROLLING_BACK: 5, ROLLED_BACK: 5, NEEDS_HUMAN: 5, FAILED: 0, CANCELLED: 0 };

/** Lifecycle progress.  Analysis-only tasks end after step 2; maintenance continues through approval to verification. */
export default function Stepper({ state, mode }: { state: string; mode: string }) {
  const steps = mode === "analysis_only" ? STEPS.slice(0, 2) : STEPS;
  const complete = state === "COMPLETED" || state === "SUCCEEDED";
  const failIdx = state in FAIL ? FAIL[state] : -1;
  const curIdx = steps.findIndex(([, st]) => st.includes(state));
  return (
    <ol className="stepper" aria-label="Workflow progress">
      {steps.map(([name], i) => {
        const cls = complete || (curIdx > i) || (failIdx > i) ? "done" : failIdx === i ? (state === "ROLLED_BACK" || state === "ROLLING_BACK" ? "warn" : "bad") : curIdx === i ? "current" : "";
        const icon = cls === "done" ? "check" : cls === "bad" ? "x" : cls === "warn" ? "rotate" : "";
        return <li key={name} className={cls} aria-current={cls === "current" ? "step" : undefined}><span className="dot">{icon ? <Icon name={icon} /> : i + 1}</span>{name}</li>;
      })}
    </ol>
  );
}
