import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../services/auth";

export default function Layout() {
  const { user, logout, can } = useAuth();
  return (
    <div className="shell">
      <nav>
        <h1>MSP AI Ops</h1>
        <NavLink to="/">Investigations</NavLink>
        <NavLink to="/approvals">Approvals</NavLink>
        <NavLink to="/clients">Clients &amp; devices</NavLink>
        <NavLink to="/reports">Reports</NavLink>
        {can("audit.read") && <NavLink to="/audit">Audit</NavLink>}
        <div className="spacer" />
        <small>{user?.email}<br />{user?.role}</small>
        <button onClick={logout}>Sign out</button>
      </nav>
      <main><Outlet /></main>
    </div>
  );
}
