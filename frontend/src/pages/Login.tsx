import { useState, type FormEvent } from "react";
import { useAuth } from "../services/auth";
import { ErrorMsg } from "../components/Common";
import { Icon } from "../components/Icons";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null); setBusy(true);
    try { await login(email, password); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="auth">
      <section className="hero">
        <div className="brand"><span className="logo" style={{ background: "#fff", color: "#184f95" }}><Icon name="shield" /></span>MSP AI Ops</div>
        <h1>Diagnose faster. Change safely.</h1>
        <p>AI interprets the evidence. A deterministic backend authorises, executes, verifies and audits every change.</p>
        <ul>
          <li><Icon name="search" /><span><b>Evidence-first diagnosis</b><br />Read-only collection, sanitised and hashed.</span></li>
          <li><Icon name="checkCircle" /><span><b>Approval of the exact plan</b><br />Backup and recovery gates block unsafe changes.</span></li>
          <li><Icon name="lock" /><span><b>Tamper-evident audit trail</b><br />Strict tenant isolation, encrypted credentials.</span></li>
        </ul>
      </section>
      <section className="panel">
        <form onSubmit={submit}>
          <h2>Sign in</h2>
          <label className="field">Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus /></label>
          <label className="field">Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
          <ErrorMsg error={error} />
          <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
      </section>
    </div>
  );
}
