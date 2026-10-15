import { useState } from "react";
import { api, type Plan } from "../services/api";
import { useAuth } from "../services/auth";
import { Badge, Card, ErrorMsg, fmt } from "./Common";
import { Icon } from "./Icons";

/** Shows the exact immutable plan.  The approver's decision carries the hash they were shown. */
export default function PlanView({ plan, onDone }: { plan: Plan; onDone: () => void }) {
  const { can } = useAuth();
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); onDone(); } catch (e) { setError((e as Error).message); } };
  return (
    <Card title={`Change plan v${plan.version}`} actions={<Badge value={plan.status} />}>
      <div className="row" style={{ marginBottom: 10 }}>
        <Badge value={plan.risk} label={`Risk: ${plan.risk.toLowerCase()}`} />
        <span className="pill info"><Icon name="rotate" />Recovery: {plan.recovery_level.toLowerCase().replace("_", " ")}</span>
        <small>Expires {fmt(plan.expires_at)}</small>
      </div>
      <ol style={{ paddingLeft: 20, margin: "0 0 10px" }}>
        {plan.steps.map((s) => (
          <li key={s.idx} style={{ marginBottom: 8 }}>
            <code>{s.operation}</code> <code>{JSON.stringify(s.params)}</code>
            <div><small>{s.rationale} · backup: {s.backup} · rollback: {s.rollback_candidates.join(", ") || "none"}</small></div>
          </li>
        ))}
      </ol>
      <small>Plan hash <code>{plan.plan_hash.slice(0, 16)}…</code> — approval binds to exactly this plan.</small>
      {plan.status === "pending_approval" && can("plan.approve") && (
        <div className="stack" style={{ marginTop: 14 }}>
          {plan.requires_second_approver && <p className="note">A second person (not the requester) must approve this plan.</p>}
          {plan.requires_no_rollback_ack && <label className="check"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />I understand this change has <b>no verified rollback</b>.</label>}
          <input placeholder="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} />
          <div className="row">
            <button onClick={() => act(() => api(`/plans/${plan.id}/decision`, { method: "POST", json: { decision: "approve", comment, plan_hash: plan.plan_hash, acknowledged_no_rollback: ack } }))}><Icon name="check" />Approve exact plan</button>
            <button className="secondary" onClick={() => act(() => api(`/plans/${plan.id}/decision`, { method: "POST", json: { decision: "reject", comment } }))}>Reject</button>
          </div>
        </div>
      )}
      {plan.status === "approved" && can("plan.execute") && (
        <div style={{ marginTop: 14 }}><button onClick={() => act(() => api(`/plans/${plan.id}/execute`, { method: "POST" }))}><Icon name="play" />Execute approved plan</button></div>
      )}
      <ErrorMsg error={error} />
    </Card>
  );
}
