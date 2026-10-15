import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, type Evidence, type Task } from "../services/api";
import { Badge, Card, ErrorMsg, fmt } from "../components/Common";
import Timeline from "../components/Timeline";
import PlanView from "../components/PlanView";

export default function TaskDetail() {
  const id = Number(useParams().id);
  const [task, setTask] = useState<Task | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    api<Task>(`/tasks/${id}`).then(setTask).catch((e) => setError(e.message));
    api<Evidence[]>(`/tasks/${id}/evidence`).then(setEvidence).catch(() => undefined);
  }, [id]);
  useEffect(load, [load]);
  if (!task) return <ErrorMsg error={error} />;
  const inv = task.investigation;
  return (
    <>
      <h2>#{task.id} {task.title} <Badge value={task.state} /></h2>
      <p><small>{task.mode === "analysis_only" ? "Analysis Only — no changes can be made" : "Troubleshooting & Maintenance"} · {task.source} · {fmt(task.created_at)}</small></p>
      <Card title="Live timeline"><Timeline key={task.state} taskId={id} onChange={load} /></Card>
      {inv && (
        <Card title="Diagnosis" actions={<small>AI: {inv.ai_used} · confidence {inv.confidence}</small>}>
          <p>{inv.summary}</p>
          <p><b>Root cause assessment:</b> {inv.root_cause || "undetermined"}</p>
          <ul>{inv.findings.map((f, i) => (
            <li key={i}><Badge value={f.severity} /> <b>{f.title}</b> <small>({f.source}; evidence {f.evidence_ids.join(", ") || "—"})</small><div><small>{f.detail}</small></div></li>
          ))}</ul>
          {inv.uncertainty.length > 0 && <><h4>Uncertainty</h4><ul>{inv.uncertainty.map((u, i) => <li key={i}>{u}</li>)}</ul></>}
          {inv.recommendations.length > 0 && <><h4>Recommendations</h4><ul>{inv.recommendations.map((u, i) => <li key={i}>{u}</li>)}</ul></>}
        </Card>
      )}
      {task.plans?.map((p) => <PlanView key={p.id} plan={p} onDone={load} />)}
      {task.runs?.map((r) => (
        <Card key={r.id} title={`Execution run ${r.id}`} actions={<Badge value={r.status} />}>
          {r.error && <p className="error">{r.error}</p>}
          <h4>Safety gates</h4>
          <ul>{Object.entries(r.gate_results).map(([k, v]) => <li key={k}>{v.ok ? "✔" : "✘"} <code>{k}</code> <small>{v.detail}</small></li>)}</ul>
          <h4>Recovery checks</h4>
          <ul>{r.recovery_checks.map((c, i) => <li key={i}>{c.passed ? "✔" : "✘"} {c.level} <small>{c.detail}</small></li>)}</ul>
          <h4>Verification</h4>
          <ul>{r.verifications.map((v, i) => <li key={i}>{v.passed ? "✔" : "✘"} {v.check} <small>{v.detail}</small></li>)}</ul>
          <h4>Before / after</h4>
          <ul>{Object.entries(r.state_diff ?? {}).map(([k, d]) => <li key={k}>step {k}: <code>{d.before}</code> → <code>{d.after}</code></li>)}</ul>
          {r.rollbacks.map((b, i) => <p key={i}>Rollback: {b.status} (state restored: {String(b.state_restored)}) {b.detail}</p>)}
        </Card>
      ))}
      <Card title={`Evidence (${evidence.length})`}>
        {evidence.map((e) => (
          <details key={e.id}>
            <summary>#{e.id} <code>{e.operation}</code> <small>[{e.phase}] exit {e.exit_code} · sha256 {e.output_sha256.slice(0, 10)}</small></summary>
            <pre>{e.command_display}{"\n\n"}{e.output_sanitized}</pre>
          </details>
        ))}
      </Card>
    </>
  );
}
