import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Evidence, type Task } from "../services/api";
import { Badge, Card, Empty, ErrorMsg, PageHeader, Skeleton, fmt } from "../components/Common";
import { Icon } from "../components/Icons";
import Timeline from "../components/Timeline";
import PlanView from "../components/PlanView";
import Stepper from "../components/Stepper";

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
  if (!task) return error ? <ErrorMsg error={error} /> : <Skeleton h={200} />;
  const inv = task.investigation;
  return (
    <>
      <PageHeader crumbs={<><Link to="/investigations">Investigations</Link> / #{task.id}</>} title={<>{task.title} <Badge value={task.state} /></>}
        subtitle={task.mode === "analysis_only" ? "Analysis Only — this investigation can never change a device." : "Troubleshooting & Maintenance — changes need an approved plan."} />
      <Stepper state={task.state} mode={task.mode} />
      <div className="grid g-detail">
        <div>
          {inv && (
            <Card title="Diagnosis" sub={`AI: ${inv.ai_used} · confidence ${inv.confidence}`}>
              <p style={{ marginTop: 0 }}>{inv.summary}</p>
              <p><b>Root-cause assessment:</b> {inv.root_cause || "undetermined"}</p>
              <ul className="list">{inv.findings.map((f, i) => (
                <li key={i} style={{ alignItems: "flex-start" }}><Badge value={f.severity} /><div className="grow"><b style={{ whiteSpace: "normal" }}>{f.title}</b><small>{f.detail} <span>({f.source}; evidence {f.evidence_ids.join(", ") || "—"})</span></small></div></li>))}</ul>
              {inv.findings.length === 0 && <Empty icon="checkCircle">No problems detected by the diagnostics that were run.</Empty>}
              {inv.uncertainty.length > 0 && <><h4>Uncertainty</h4><ul>{inv.uncertainty.map((u, i) => <li key={i}>{u}</li>)}</ul></>}
              {inv.recommendations.length > 0 && <><h4 style={{ marginTop: 12 }}>Recommendations</h4><ul>{inv.recommendations.map((u, i) => <li key={i}>{u}</li>)}</ul></>}
            </Card>
          )}
          {task.plans?.map((p) => <PlanView key={p.id} plan={p} onDone={load} />)}
          {task.runs?.map((r) => (
            <Card key={r.id} title={`Execution run ${r.id}`} actions={<Badge value={r.status} />}>
              {r.error && <p className="error">{r.error}</p>}
              <h4 style={{ margin: "8px 0" }}>Safety gates</h4>
              <ul className="gate-list">{Object.entries(r.gate_results).map(([k, v]) => <li key={k} className={v.ok ? "ok" : "bad"}><Icon name={v.ok ? "check" : "x"} /><code>{k}</code><small>{v.detail}</small></li>)}</ul>
              <h4 style={{ margin: "14px 0 8px" }}>Recovery &amp; verification</h4>
              <ul className="gate-list">
                {r.recovery_checks.map((c, i) => <li key={"c" + i} className={c.passed ? "ok" : "bad"}><Icon name={c.passed ? "check" : "x"} />Recovery {c.level.toLowerCase().replace("_", " ")}<small>{c.detail}</small></li>)}
                {r.verifications.map((v, i) => <li key={"v" + i} className={v.passed ? "ok" : "bad"}><Icon name={v.passed ? "check" : "x"} />{v.check}<small>{v.detail}</small></li>)}
              </ul>
              {Object.keys(r.state_diff ?? {}).length > 0 && <><h4 style={{ margin: "14px 0 8px" }}>Before → after</h4>
                <ul className="list">{Object.entries(r.state_diff).map(([k, d]) => <li key={k}>Step {Number(k) + 1}<code>{d.before}</code><Icon name="play" /><code>{d.after}</code></li>)}</ul></>}
              {r.rollbacks.map((b, i) => <p key={i} className="note">Rollback {b.status} (state restored: {String(b.state_restored)}). {b.detail}</p>)}
            </Card>
          ))}
          <Card title={`Evidence (${evidence.length})`} sub="Sanitised, hashed command output">
            {evidence.length === 0 ? <Empty icon="doc">Nothing collected yet.</Empty> : evidence.map((e) => (
              <details key={e.id}>
                <summary>#{e.id} <code>{e.operation}</code> <small>{e.phase} · exit {e.exit_code} · sha256 {e.output_sha256.slice(0, 10)}</small></summary>
                <pre>{e.command_display}{"\n\n"}{e.output_sanitized}</pre>
              </details>))}
          </Card>
        </div>
        <aside>
          <Card title="Details">
            <dl className="kv"><dt>Mode</dt><dd>{task.mode === "analysis_only" ? "Analysis Only" : "Maintenance"}</dd><dt>Source</dt><dd>{task.source}{task.source_ref ? ` #${task.source_ref}` : ""}</dd>
              <dt>Started</dt><dd>{fmt(task.created_at)}</dd><dt>Finished</dt><dd>{fmt(task.completed_at)}</dd></dl>
            {task.description && <><h4 style={{ margin: "12px 0 4px", fontSize: 12.5 }} className="muted">Symptoms</h4><p style={{ margin: 0 }}>{task.description}</p></>}
          </Card>
          <Card title="Live timeline"><Timeline key={task.state} taskId={id} onChange={load} /></Card>
        </aside>
      </div>
    </>
  );
}
