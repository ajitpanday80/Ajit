import { useEffect, useState } from "react";

type Theme = "system" | "light" | "dark";
const KEY = "msp_theme";
const read = (): Theme => { try { return (localStorage.getItem(KEY) as Theme) || "system"; } catch { return "system"; } };

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(read);
  useEffect(() => {
    const el = document.documentElement;
    if (theme === "system") el.removeAttribute("data-theme"); else el.setAttribute("data-theme", theme);
    try { localStorage.setItem(KEY, theme); } catch { /* storage may be blocked */ }
  }, [theme]);
  const dark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  return { theme, dark, toggle: () => setTheme(dark ? "light" : "dark") };
}
