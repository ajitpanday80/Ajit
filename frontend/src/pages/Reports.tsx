import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { Card, Empty, PageHeader, Skeleton, fmt } from "../components/Common";

interface Row { id: number; task_id: number; title: string; created_at: string }
export default function Reports() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [open, setOpen] = useState<{ id: number; content: string } | null>(null);
  useEffect(() => { api<Row[]>("/reports").then(setRows).catch(() => setRows([])); }, []);
  const show = (taskId: number) => api<{ content: string }>(`/tasks/${taskId}/report`).then((r) => setOpen({ id: taskId, content: r.content }));
  return (
    <>
      <PageHeader title="Reports" subtitle="Generated automatically for every finished investigation." />
      <div className="grid" style={{ gridTemplateColumns: open ? "minmax(0,1fr) minmax(0,1.6fr)" : "1fr" }}>
        <Card>{!rows ? <Skeleton h={100} /> : rows.length === 0 ? <Empty icon="doc">No reports yet.</Empty> : (
          <ul className="list">{rows.map((r) => (
            <li key={r.id}><div className="grow"><a href="#" onClick={(e) => { e.preventDefault(); show(r.task_id); }}><b>{r.title}</b></a><small>{fmt(r.created_at)}</small></div><Link to={`/tasks/${r.task_id}`}>Open task</Link></li>))}</ul>)}</Card>
        {open && <Card title={`Report for investigation #${open.id}`} actions={<button className="ghost" onClick={() => window.print()}>Print</button>}><pre className="report">{open.content}</pre></Card>}
      </div>
    </>
  );
}
