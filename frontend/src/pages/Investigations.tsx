import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type Device, type Task } from "../services/api";
import { useAuth } from "../services/auth";
import { Badge, Card, Empty, ErrorMsg, PageHeader, Skeleton, ago } from "../components/Common";
import { Icon } from "../components/Icons";

const FILTERS = [["", "All"], ["AWAITING_APPROVAL", "Awaiting approval"], ["COMPLETED", "Completed"], ["SUCCEEDED", "Succeeded"], ["NEEDS_HUMAN", "Needs human"]];

export default function Investigations() {
  const { can } = useAuth();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const [tasks, setTasks] = useState<Task[] | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [filter, setFilter] = useState("");
  const [form, setForm] = useState({ device_id: "", title: "", description: "", mode: "analysis_only" });
  const [error, setError] = useState<string | null>(null);
  const showForm = params.get("new") === "1";
  useEffect(() => { api<Task[]>("/tasks").then(setTasks).catch((e) => setError(e.message)); api<Device[]>("/devices").then(setDevices).catch(() => undefined); }, []);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setError(null);
    try { const t = await api<Task>("/tasks", { method: "POST", json: { ...form, device_id: Number(form.device_id) } }); nav(`/tasks/${t.id}`); }
    catch (err) { setError((err as Error).message); }
  };
  const shown = (tasks ?? []).filter((t) => !filter || t.state === filter);
  return (
    <>
      <PageHeader title="Investigations" subtitle="Every request, its evidence and outcome."
        actions={can("task.create") && <button onClick={() => setParams(showForm ? {} : { new: "1" })}><Icon name="search" />{showForm ? "Close" : "New investigation"}</button>} />
      {showForm && (
        <Card title="New investigation" sub="Analysis Only never changes anything; Maintenance proposes a plan that needs approval.">
          <form className="row" onSubmit={submit} style={{ alignItems: "flex-end" }}>
            <label className="field">Device<select value={form.device_id} onChange={(e) => setForm({ ...form, device_id: e.target.value })} required>
              <option value="">Select…</option>{devices.map((d) => <option key={d.id} value={d.id}>{d.hostname} ({d.device_type})</option>)}</select></label>
            <label className="field" style={{ flex: 1, minWidth: 180 }}>Title<input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required /></label>
            <label className="field" style={{ flex: 1, minWidth: 200 }}>Symptoms<input placeholder="e.g. service:nginx.service is down" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
            <label className="field">Mode<select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
              <option value="analysis_only">Analysis Only</option>{can("task.run_maintenance") && <option value="maintenance">Troubleshooting &amp; Maintenance</option>}</select></label>
            <button type="submit">Start</button>
          </form>
          <ErrorMsg error={error} />
        </Card>
      )}
      <Card>
        <div className="seg" role="group" aria-label="Filter by state" style={{ marginBottom: 12 }}>{FILTERS.map(([v, l]) => <button key={v} aria-pressed={filter === v} onClick={() => setFilter(v)}>{l}</button>)}</div>
        {!tasks ? <Skeleton h={120} /> : shown.length === 0 ? <Empty>No investigations match.</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>#</th><th>Title</th><th>Mode</th><th>State</th><th>Source</th><th>Started</th></tr></thead>
            <tbody>{shown.map((t) => (
              <tr key={t.id}><td className="muted">{t.id}</td><td><Link to={`/tasks/${t.id}`}><b>{t.title}</b></Link></td>
                <td>{t.mode === "analysis_only" ? "Analysis Only" : "Maintenance"}</td><td><Badge value={t.state} /></td><td className="muted">{t.source}</td><td className="muted">{ago(t.created_at)}</td></tr>))}</tbody>
          </table></div>)}
        <ErrorMsg error={showForm ? null : error} />
      </Card>
    </>
  );
}
