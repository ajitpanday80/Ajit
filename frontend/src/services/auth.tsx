import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, setToken, type User } from "./api";

interface AuthCtx { user: User | null; loading: boolean; login(email: string, password: string): Promise<void>; logout(): Promise<void>; can(p: string): boolean }
const Ctx = createContext<AuthCtx>(null!);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(!!getToken());
  useEffect(() => {
    if (!getToken()) return;
    api<User>("/auth/me").then(setUser).catch(() => setToken(null)).finally(() => setLoading(false));
  }, []);
  const login = useCallback(async (email: string, password: string) => {
    const r = await api<{ token: string }>("/auth/login", { method: "POST", json: { email, password } });
    setToken(r.token);
    setUser(await api<User>("/auth/me"));
  }, []);
  const logout = useCallback(async () => {
    try { await api("/auth/logout", { method: "POST" }); } catch { /* token may already be invalid */ }
    setToken(null); setUser(null);
  }, []);
  const can = useCallback((p: string) => !!user?.permissions?.includes(p), [user]);
  return <Ctx.Provider value={{ user, loading, login, logout, can }}>{children}</Ctx.Provider>;
}
