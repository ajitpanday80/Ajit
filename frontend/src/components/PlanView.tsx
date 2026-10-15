import { useState } from "react";
import { api, type Plan } from "../services/api";
import { useAuth } from "../services/auth";
import { Badge, Card, ErrorMsg, fmt } from "./Common";

/** Shows the exact immutable plan.  The approver's decision carries the hash they were shown. */
export default function PlanView({ plan, onDone }: { plan: Plan; onDone: () => void }) {
  const { can } = useAuth();
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); onDone(); } catch (e) { setError((e as Error).message); } };
  return (
    <Card title={`Change plan v${plan.version}`} actions={<Badge value={plan.status} />}>
      <p><small>Hash <code>{plan.plan_hash}</code> · risk <Badge value={plan.risk.toLowerCase()} /> · recovery <b>{plan.recovery_level}</b> · expires {fmt(plan.expires_at)}</small></p>
      <ol>
        {plan.steps.map((s) => (
          <li key={s.idx}>
            <code>{s.operation}</code> <code>{JSON.stringify(s.params)}</code>
            <div><small>{s.rationale} · backup: {s.backup} · rollback: {s.rollback_candidates.join(", ") || "none"}</small></div>
          </li>
        ))}
      </ol>
      {plan.status === "pending_approval" && can("plan.approve") && (
        <div className="stack">
          {plan.requires_second_approver && <p className="note">A second person (not the requester) must approve this plan.</p>}
          {plan.requires_no_rollback_ack && (
            <label className="check"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I understand this change has <b>no verified rollback</b>.</label>
          )}
          <input placeholder="Comment" value={comment} onChange={(e) => setComment(e.target.value)} />
          <div className="row">
            <button onClick={() => act(() => api(`/plans/${plan.id}/decision`, { method: "POST", json: { decision: "approve", comment, plan_hash: plan.plan_hash, acknowledged_no_rollback: ack } }))}>Approve exact plan</button>
            <button className="secondary" onClick={() => act(() => api(`/plans/${plan.id}/decision`, { method: "POST", json: { decision: "reject", comment } }))}>Reject</button>
          </div>
        </div>
      )}
      {plan.status === "approved" && can("plan.execute") && (
        <button onClick={() => act(() => api(`/plans/${plan.id}/execute`, { method: "POST" }))}>Execute approved plan</button>
      )}
      <ErrorMsg error={error} />
    </Card>
  );
}
