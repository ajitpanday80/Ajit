import { useEffect, useState, type FormEvent } from "react";
import { api, type Client, type Device } from "../services/api";
import { useAuth } from "../services/auth";
import { Badge, Card, Empty, ErrorMsg, PageHeader } from "../components/Common";
import { Icon } from "../components/Icons";

export default function Clients() {
  const { can, user } = useAuth();
  const [clients, setClients] = useState<Client[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [name, setName] = useState("");
  const [dev, setDev] = useState({ client_id: "", hostname: "", address: "", device_type: "linux" });
  const [error, setError] = useState<string | null>(null);
  const load = () => { api<Client[]>("/clients").then(setClients); api<Device[]>("/devices").then(setDevices); };
  useEffect(() => { load(); }, []);
  const run = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); load(); return true; } catch (e) { setError((e as Error).message); return false; } };
  return (
    <>
      <PageHeader title="Clients & devices" subtitle="Tenant-separated clients and the devices the platform may diagnose." />
      <ErrorMsg error={error} />
      {can("inventory.write") && (
        <Card title="Add">
          <form className="row" style={{ alignItems: "flex-end" }} onSubmit={async (e: FormEvent) => { e.preventDefault(); if (await run(() => api("/clients", { method: "POST", json: { name } }))) setName(""); }}>
            <label className="field" style={{ flex: 1, minWidth: 200 }}>Client name<input value={name} onChange={(e) => setName(e.target.value)} required /></label><button>Add client</button>
          </form>
          <hr style={{ border: 0, borderTop: "1px solid var(--line)", margin: "14px 0" }} />
          <form className="row" style={{ alignItems: "flex-end" }} onSubmit={(e: FormEvent) => { e.preventDefault(); run(() => api("/devices", { method: "POST", json: { ...dev, client_id: Number(dev.client_id) } })); }}>
            <label className="field">Client<select value={dev.client_id} onChange={(e) => setDev({ ...dev, client_id: e.target.value })} required><option value="">Select…</option>{clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
            <label className="field">Hostname<input value={dev.hostname} onChange={(e) => setDev({ ...dev, hostname: e.target.value })} required /></label>
            <label className="field">Address<input value={dev.address} onChange={(e) => setDev({ ...dev, address: e.target.value })} required /></label>
            <label className="field">Type<select value={dev.device_type} onChange={(e) => setDev({ ...dev, device_type: e.target.value })}>{["linux", "windows", "voip", "web", "router", "firewall", "hyperv", "backup"].map((t) => <option key={t}>{t}</option>)}</select></label>
            <button>Add device</button>
          </form>
        </Card>
      )}
      {clients.length === 0 && <Card><Empty icon="users">No clients yet.</Empty></Card>}
      {clients.map((c) => (
        <Card key={c.id} title={c.name} sub={`${devices.filter((d) => d.client_id === c.id).length} devices`} actions={
          <span className="row">
            <span className="pill info"><Icon name="lock" />AI: {c.ai_policy.replace("_", " ")}</span>
            <Badge value={c.maintenance_enabled ? "approved" : "info"} label={c.maintenance_enabled ? "Maintenance enabled" : "Analysis only"} />
            {user?.role === "tenant_admin" && <button className="secondary" onClick={() => run(() => api(`/clients/${c.id}`, { method: "PATCH", json: { maintenance_enabled: !c.maintenance_enabled } }))}>{c.maintenance_enabled ? "Disable" : "Enable"} maintenance</button>}
          </span>}>
          {devices.filter((d) => d.client_id === c.id).length === 0 ? <small>No devices.</small> : (
            <div className="table-wrap"><table><thead><tr><th>Hostname</th><th>Address</th><th>Type</th><th>Connector</th></tr></thead><tbody>
              {devices.filter((d) => d.client_id === c.id).map((d) => <tr key={d.id}><td><b>{d.hostname}</b></td><td className="muted">{d.address}</td><td>{d.device_type}</td><td className="muted">{d.connector}</td></tr>)}</tbody></table></div>)}
        </Card>
      ))}
    </>
  );
}
