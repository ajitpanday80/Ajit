import { useState, type FormEvent } from "react";
import { useAuth } from "../services/auth";
import { ErrorMsg } from "../components/Common";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try { await login(email, password); } catch (err) { setError((err as Error).message); }
  };
  return (
    <form className="login card" onSubmit={submit}>
      <h2>Sign in</h2>
      <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required /></label>
      <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
      <ErrorMsg error={error} />
      <button type="submit">Sign in</button>
    </form>
  );
}
