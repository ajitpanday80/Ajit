import { useEffect, useState, type FormEvent } from "react";
import { api, type Client, type Device } from "../services/api";
import { useAuth } from "../services/auth";
import { Badge, Card, ErrorMsg } from "../components/Common";

export default function Clients() {
  const { can, user } = useAuth();
  const [clients, setClients] = useState<Client[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [name, setName] = useState("");
  const [dev, setDev] = useState({ client_id: "", hostname: "", address: "", device_type: "linux" });
  const [error, setError] = useState<string | null>(null);
  const load = () => { api<Client[]>("/clients").then(setClients); api<Device[]>("/devices").then(setDevices); };
  useEffect(() => { load(); }, []);
  const run = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); load(); } catch (e) { setError((e as Error).message); } };
  return (
    <>
      <h2>Clients &amp; devices</h2>
      <ErrorMsg error={error} />
      {can("inventory.write") && (
        <Card title="Add">
          <form className="row" onSubmit={(e: FormEvent) => { e.preventDefault(); run(() => api("/clients", { method: "POST", json: { name } })).then(() => setName("")); }}>
            <input placeholder="Client name" value={name} onChange={(e) => setName(e.target.value)} required /><button>Add client</button>
          </form>
          <form className="row" onSubmit={(e: FormEvent) => { e.preventDefault(); run(() => api("/devices", { method: "POST", json: { ...dev, client_id: Number(dev.client_id) } })); }}>
            <select value={dev.client_id} onChange={(e) => setDev({ ...dev, client_id: e.target.value })} required>
              <option value="">Client…</option>{clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <input placeholder="Hostname" value={dev.hostname} onChange={(e) => setDev({ ...dev, hostname: e.target.value })} required />
            <input placeholder="Address" value={dev.address} onChange={(e) => setDev({ ...dev, address: e.target.value })} required />
            <select value={dev.device_type} onChange={(e) => setDev({ ...dev, device_type: e.target.value })}>
              {["linux", "windows", "voip", "web", "router", "firewall", "hyperv", "backup"].map((t) => <option key={t}>{t}</option>)}
            </select>
            <button>Add device</button>
          </form>
        </Card>
      )}
      {clients.map((c) => (
        <Card key={c.id} title={c.name} actions={
          <span className="row">
            <small>AI: {c.ai_policy}</small>
            <Badge value={c.maintenance_enabled ? "approved" : "info"} />
            {user?.role === "tenant_admin" && (
              <button className="secondary" onClick={() => run(() => api(`/clients/${c.id}`, { method: "PATCH", json: { maintenance_enabled: !c.maintenance_enabled } }))}>
                {c.maintenance_enabled ? "Disable" : "Enable"} maintenance
              </button>
            )}
          </span>}>
          <ul>{devices.filter((d) => d.client_id === c.id).map((d) => <li key={d.id}>{d.hostname} <small>{d.address} · {d.device_type} · {d.connector}</small></li>)}</ul>
        </Card>
      ))}
    </>
  );
}
