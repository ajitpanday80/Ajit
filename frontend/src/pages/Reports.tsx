import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { Card, fmt } from "../components/Common";

interface Row { id: number; task_id: number; title: string; created_at: string }
export default function Reports() {
  const [rows, setRows] = useState<Row[]>([]);
  const [open, setOpen] = useState<{ id: number; content: string } | null>(null);
  useEffect(() => { api<Row[]>("/reports").then(setRows).catch(() => undefined); }, []);
  const show = (taskId: number) => api<{ content: string }>(`/tasks/${taskId}/report`).then((r) => setOpen({ id: taskId, content: r.content }));
  return (
    <>
      <h2>Incident reports</h2>
      <Card><ul>{rows.map((r) => <li key={r.id}><a href="#" onClick={(e) => { e.preventDefault(); show(r.task_id); }}>{r.title}</a> <small>{fmt(r.created_at)} · <Link to={`/tasks/${r.task_id}`}>task</Link></small></li>)}</ul></Card>
      {open && <Card title={`Report for task #${open.id}`}><pre className="report">{open.content}</pre></Card>}
    </>
  );
}
