import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Device, type Task } from "../services/api";
import { useAuth } from "../services/auth";
import { Badge, Card, ErrorMsg, fmt } from "../components/Common";

export default function Investigations() {
  const { can } = useAuth();
  const nav = useNavigate();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [form, setForm] = useState({ device_id: "", title: "", description: "", mode: "analysis_only" });
  const [error, setError] = useState<string | null>(null);
  const load = () => api<Task[]>("/tasks").then(setTasks).catch((e) => setError(e.message));
  useEffect(() => { load(); api<Device[]>("/devices").then(setDevices).catch(() => undefined); }, []);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const t = await api<Task>("/tasks", { method: "POST", json: { ...form, device_id: Number(form.device_id) } });
      nav(`/tasks/${t.id}`);
    } catch (err) { setError((err as Error).message); }
  };
  return (
    <>
      <h2>Investigations</h2>
      {can("task.create") && (
        <Card title="New investigation">
          <form className="row" onSubmit={submit}>
            <select value={form.device_id} onChange={(e) => setForm({ ...form, device_id: e.target.value })} required>
              <option value="">Select device…</option>
              {devices.map((d) => <option key={d.id} value={d.id}>{d.hostname} ({d.device_type})</option>)}
            </select>
            <input placeholder="Title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required />
            <input placeholder="Description (hint: service:nginx.service)" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
              <option value="analysis_only">Analysis Only</option>
              {can("task.run_maintenance") && <option value="maintenance">Troubleshooting &amp; Maintenance</option>}
            </select>
            <button type="submit">Start</button>
          </form>
          <ErrorMsg error={error} />
        </Card>
      )}
      <Card>
        <table>
          <thead><tr><th>#</th><th>Title</th><th>Mode</th><th>State</th><th>Created</th></tr></thead>
          <tbody>
            {tasks.map((t) => (
              <tr key={t.id}>
                <td>{t.id}</td><td><Link to={`/tasks/${t.id}`}>{t.title}</Link></td>
                <td>{t.mode === "analysis_only" ? "Analysis Only" : "Maintenance"}</td><td><Badge value={t.state} /></td><td>{fmt(t.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
