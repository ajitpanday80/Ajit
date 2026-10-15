import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Summary } from "../services/api";
import { useAuth } from "../services/auth";
import { Badge, Card, Empty, PageHeader, Skeleton, ago } from "../components/Common";
import { BarList, ColumnChart, Meter, Sparkline } from "../components/Charts";
import { Icon } from "../components/Icons";

const SEV_COLOR: Record<string, string> = { critical: "var(--critical)", high: "var(--serious)", medium: "var(--warning)", low: "var(--series)", info: "var(--line-2)" };
const RANGES = [7, 14, 30, 90];
const TYPE_NAMES: Record<string, string> = { linux: "Linux", windows: "Windows", voip: "VoIP / PBX", web: "Web", router: "Routers", firewall: "Firewalls", hyperv: "Hyper-V", backup: "Backup" };
const dur = (m: number) => (m < 90 ? `${m} min` : m < 2880 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`);

export default function Overview() {
  const { user, can } = useAuth();
  const [days, setDays] = useState(14);
  const [data, setData] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setLoading(true);
    api<Summary>(`/dashboard/summary?days=${days}`).then(setData).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, [days]);
  const hour = new Date().getHours();
  const hello = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
  const k = data?.kpis;
  return (
    <>
      <PageHeader title={`${hello}${user?.name ? ", " + user.name : ""}`} subtitle="Operational health across all clients."
        actions={<>
          <div className="seg" role="group" aria-label="Date range">{RANGES.map((r) => <button key={r} aria-pressed={days === r} onClick={() => setDays(r)}>{r}d</button>)}</div>
          {can("task.create") && <Link className="btn" to="/investigations?new=1"><Icon name="search" />New investigation</Link>}
        </>} />
      {error && <p className="error" role="alert">{error}</p>}
      {!data ? <div className="grid g-kpi">{[0, 1, 2, 3].map((i) => <div className="card" key={i}><Skeleton h={80} /></div>)}</div> : (
        <div style={{ opacity: loading ? 0.6 : 1, transition: "opacity .15s" }}>
          <div className="grid g-kpi">
            <Card className="stat"><div className="label"><Icon name="activity" />Open investigations</div>
              <div className="value">{k!.open}</div><div className="foot"><span>{k!.investigations} started in {days}d</span><Sparkline values={data.per_day.map((d) => d.count)} label="Investigations per day" /></div></Card>
            <Card className={`stat ${k!.awaiting_approval ? "alert" : ""}`}><div className="label"><Icon name="clock" />Awaiting approval</div>
              <div className="value">{k!.awaiting_approval}</div><div className="foot"><span>{k!.awaiting_approval ? "Changes are blocked until approved" : "Nothing waiting"}</span>{k!.awaiting_approval > 0 && can("plan.approve") && <Link to="/approvals">Review →</Link>}</div></Card>
            <Card className="stat"><div className="label"><Icon name="checkCircle" />Change success rate</div>
              <div className="value">{k!.success_rate === null ? "—" : k!.success_rate}{k!.success_rate !== null && <small>%</small>}</div>
              <div className="foot" style={{ display: "block" }}>{k!.success_rate !== null && <Meter pct={k!.success_rate} label="Change success rate" />}<span>{k!.runs_finished ? `${k!.runs_finished} verified run${k!.runs_finished > 1 ? "s" : ""}` : "No approved changes yet"}</span></div></Card>
            <Card className="stat"><div className="label"><Icon name="alert" />High-severity findings</div>
              <div className="value">{k!.high_findings}</div><div className="foot"><span>critical + high, last {days}d</span>{k!.mttr_minutes !== null && <span>avg {dur(k!.mttr_minutes)} to finish</span>}</div></Card>
          </div>

          <div className="grid g-2">
            <Card title="Investigations per day" sub={`last ${days} days`}>
              {data.kpis.investigations === 0 ? <Empty icon="search">No investigations in this period.</Empty> : <>
                <ColumnChart unit="investigation" data={data.per_day.map((d) => ({ label: d.date, value: d.count }))} />
                <details><summary><small>View as table</small></summary>
                  <div className="table-wrap"><table><thead><tr><th>Date</th><th className="num">Investigations</th></tr></thead><tbody>
                    {data.per_day.filter((d) => d.count).map((d) => <tr key={d.date}><td>{d.date}</td><td className="num">{d.count}</td></tr>)}</tbody></table></div></details></>}
            </Card>
            <Card title="Findings by severity" sub={`last ${days}d`}>
              {data.by_severity.every((s) => !s.count) ? <Empty icon="checkCircle">No findings recorded.</Empty> :
                <BarList items={data.by_severity.map((s) => ({ label: s.severity, value: s.count, color: SEV_COLOR[s.severity] }))} />}
            </Card>
          </div>

          <div className="grid g-3">
            <Card title="Needs attention" actions={<Link to="/investigations">All →</Link>}>
              {data.attention.length === 0 ? <Empty icon="checkCircle">All clear.</Empty> : <ul className="list">{data.attention.map((a) => (
                <li key={a.id}><div className="grow"><Link to={`/tasks/${a.id}`}><b>{a.title}</b></Link><small>{ago(a.at)}</small></div><Badge value={a.state} /></li>))}</ul>}
            </Card>
            <Card title="Recent activity">
              {data.recent.length === 0 ? <Empty icon="activity">No activity yet.</Empty> : <ul className="list">{data.recent.map((r, i) => (
                <li key={i}><div className="grow"><Link to={`/tasks/${r.task_id}`}><b>{r.title}</b></Link><small>{r.actor} · {ago(r.at)}</small></div><Badge value={r.to_state} /></li>))}</ul>}
            </Card>
            <Card title="Workload by device type" sub={`last ${days}d`} className="">
              {data.by_device_type.length === 0 ? <Empty icon="server">No data.</Empty> : <BarList items={data.by_device_type.map((d) => ({ label: TYPE_NAMES[d.type] ?? d.type, value: d.count }))} />}
              <div style={{ height: 14 }} />
              <h4 style={{ fontSize: 13, marginBottom: 8 }}>Safety posture</h4>
              <div className="posture">
                <div className="p"><Icon name="lock" />Audit chain<b>{data.posture.audit_chain_ok ? <Badge value="COMPLETED" label="Intact" /> : <Badge value="FAILED" label="Broken" />}</b></div>
                <div className="p"><Icon name="shield" />Maintenance enabled<b>{data.posture.maintenance_enabled} / {data.posture.clients} clients</b></div>
                <div className="p"><Icon name="server" />Local-only AI clients<b>{data.posture.local_only} / {data.posture.clients}</b></div>
              </div>
            </Card>
          </div>
        </div>)}
    </>
  );
}
