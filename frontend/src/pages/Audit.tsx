import { useEffect, useState } from "react";
import { api } from "../services/api";
import { Card, fmt } from "../components/Common";

interface Ev { seq: number; actor: string; action: string; object_type: string; object_id: string; at: string; hash: string }
export default function Audit() {
  const [events, setEvents] = useState<Ev[]>([]);
  const [chain, setChain] = useState<string>("");
  useEffect(() => { api<Ev[]>("/audit?limit=200").then(setEvents).catch(() => undefined); }, []);
  const verify = async () => { const r = await api<{ ok: boolean; first_bad_seq: number | null }>("/audit/verify"); setChain(r.ok ? "Hash chain intact ✔" : `Chain BROKEN at #${r.first_bad_seq} ✘`); };
  return (
    <>
      <h2>Audit trail</h2>
      <Card actions={<button onClick={verify}>Verify chain</button>}>
        <p>{chain}</p>
        <table><thead><tr><th>#</th><th>When</th><th>Actor</th><th>Action</th><th>Object</th></tr></thead>
          <tbody>{events.map((e) => <tr key={e.seq}><td>{e.seq}</td><td>{fmt(e.at)}</td><td>{e.actor}</td><td>{e.action}</td><td>{e.object_type} {e.object_id}</td></tr>)}</tbody></table>
      </Card>
    </>
  );
}
