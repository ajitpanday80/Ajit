import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api, type Plan } from "../services/api";
import { useAuth } from "../services/auth";
import { useTheme } from "../services/theme";
import { Icon } from "./Icons";

export default function Layout() {
  const { user, logout, can } = useAuth();
  const { dark, toggle } = useTheme();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(0);
  const loc = useLocation();
  useEffect(() => setOpen(false), [loc.pathname]);
  useEffect(() => {
    if (!can("plan.approve")) return;
    const load = () => api<Plan[]>("/plans?status=pending_approval").then((p) => setPending(p.length)).catch(() => undefined);
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [can]);
  const link = (to: string, icon: string, text: string, end = false, badge?: number) => (
    <NavLink to={to} end={end} className="link"><Icon name={icon} />{text}{!!badge && <span className="count">{badge}</span>}</NavLink>
  );
  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand"><span className="logo"><Icon name="shield" /></span><span>MSP AI Ops<small>Infrastructure operations</small></span></div>
        <span className="nav-label">Operate</span>
        {link("/", "home", "Overview", true)}
        {link("/investigations", "search", "Investigations")}
        {link("/approvals", "checkCircle", "Approvals", false, pending)}
        <span className="nav-label">Manage</span>
        {link("/clients", "server", "Clients & devices")}
        {link("/reports", "doc", "Reports")}
        {can("audit.read") && link("/audit", "list", "Audit trail")}
        <div className="spacer" />
        <div className="userbox">
          <span className="avatar">{user?.email.slice(0, 2)}</span>
          <span className="who"><b>{user?.email}</b><small>{user?.role.replace("_", " ")}</small></span>
          <button className="ghost" onClick={logout} aria-label="Sign out" title="Sign out"><Icon name="logout" /></button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="ghost menu-btn" onClick={() => setOpen(!open)} aria-label="Menu"><Icon name="menu" /></button>
          <span className="grow" />
          <button className="ghost" onClick={toggle} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"} title="Toggle theme"><Icon name={dark ? "sun" : "moon"} /></button>
        </header>
        <div className="content"><Outlet /></div>
      </div>
    </div>
  );
}
