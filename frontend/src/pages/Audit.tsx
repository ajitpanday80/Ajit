import { useEffect, useState } from "react";
import { api } from "../services/api";
import { Badge, Card, PageHeader, fmt } from "../components/Common";
import { Icon } from "../components/Icons";

interface Ev { seq: number; actor: string; action: string; object_type: string; object_id: string; at: string; hash: string }
export default function Audit() {
  const [events, setEvents] = useState<Ev[]>([]);
  const [chain, setChain] = useState<boolean | null>(null);
  useEffect(() => { api<Ev[]>("/audit?limit=200").then(setEvents).catch(() => undefined); }, []);
  const verify = async () => setChain((await api<{ ok: boolean }>("/audit/verify")).ok);
  return (
    <>
      <PageHeader title="Audit trail" subtitle="Append-only and hash-chained: any edit or deletion is detectable."
        actions={<>{chain !== null && <Badge value={chain ? "COMPLETED" : "FAILED"} label={chain ? "Chain intact" : "Chain broken"} />}<button onClick={verify}><Icon name="lock" />Verify chain</button></>} />
      <Card><div className="table-wrap"><table>
        <thead><tr><th className="num">#</th><th>When</th><th>Actor</th><th>Action</th><th>Object</th><th>Hash</th></tr></thead>
        <tbody>{events.map((e) => <tr key={e.seq}><td className="num muted">{e.seq}</td><td className="muted">{fmt(e.at)}</td><td>{e.actor}</td><td><code>{e.action}</code></td><td>{e.object_type} {e.object_id}</td><td><code>{e.hash.slice(0, 10)}</code></td></tr>)}</tbody></table></div></Card>
    </>
  );
}
