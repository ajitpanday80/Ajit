import { useState } from "react";

/* Charts follow the dataviz method: one hue for one series, thin rounded-end marks anchored to the baseline,
   recessive grid, direct labels, a hover/focus tooltip, and a table fallback via <details> in the caller. */

interface Tip { x: number; y: number; title: string; value: string }
const Tooltip = ({ tip }: { tip: Tip | null }) => tip ? <div className="tooltip" style={{ left: tip.x, top: tip.y }}><b>{tip.value}</b><span>{tip.title}</span></div> : null;

export function Sparkline({ values, label }: { values: number[]; label: string }) {
  const w = 96, h = 28, max = Math.max(1, ...values);
  const pts = values.map((v, i) => [(i / Math.max(values.length - 1, 1)) * (w - 4) + 2, h - 3 - (v / max) * (h - 8)]);
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label}>
      <polyline fill="none" stroke="var(--series)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" points={pts.map((p) => p.join(",")).join(" ")} />
      {pts.length > 0 && <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="3" fill="var(--series)" stroke="var(--surface)" strokeWidth="2" />}
    </svg>
  );
}

export function ColumnChart({ data, unit }: { data: { label: string; value: number }[]; unit: string }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const [hot, setHot] = useState<number | null>(null);
  const W = 640, H = 200, pad = { l: 28, r: 8, t: 10, b: 24 };
  const max = Math.max(4, ...data.map((d) => d.value));
  const top = Math.ceil(max / 4) * 4;
  const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b, slot = iw / data.length, bw = Math.min(22, slot * 0.6);
  const every = Math.ceil(data.length / 7);
  const show = (i: number, el: SVGElement) => {
    const r = el.ownerSVGElement!.getBoundingClientRect();
    setHot(i);
    setTip({ x: ((pad.l + slot * (i + 0.5)) / W) * r.width, y: ((pad.t + ih - (data[i].value / top) * ih) / H) * r.height, title: data[i].label, value: `${data[i].value} ${unit}${data[i].value === 1 ? "" : "s"}` });
  };
  return (
    <div className="chart" onMouseLeave={() => { setTip(null); setHot(null); }}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${unit}s per day, ${data.reduce((a, d) => a + d.value, 0)} in total`}>
        {[0, 1, 2, 3, 4].map((g) => {
          const y = pad.t + ih - (g / 4) * ih;
          return <g key={g}><line className={g === 0 ? "axis-line" : "grid-line"} x1={pad.l} x2={W - pad.r} y1={y} y2={y} /><text x={pad.l - 6} y={y + 4} textAnchor="end">{(top * g) / 4}</text></g>;
        })}
        {data.map((d, i) => {
          const bh = (d.value / top) * ih, x = pad.l + slot * i + (slot - bw) / 2, y = pad.t + ih - bh;
          return (
            <g key={i}>
              {d.value > 0 && <path className={`bar ${hot !== null && hot !== i ? "dim" : ""}`} d={`M${x},${y + bh} V${y + 4} a4,4 0 0 1 4,-4 h${bw - 8} a4,4 0 0 1 4,4 V${y + bh} Z`} />}
              {d.value === 0 && <rect x={x} y={pad.t + ih - 2} width={bw} height="2" rx="1" fill="var(--line-2)" />}
              <rect x={pad.l + slot * i} y={pad.t} width={slot} height={ih + 4} fill="transparent" tabIndex={0} role="img" aria-label={`${d.label}: ${d.value}`}
                onMouseMove={(e) => show(i, e.currentTarget)} onFocus={(e) => show(i, e.currentTarget)} onBlur={() => { setTip(null); setHot(null); }} />
              {i % every === 0 && <text x={pad.l + slot * (i + 0.5)} y={H - 6} textAnchor="middle">{d.label.slice(5)}</text>}
            </g>
          );
        })}
      </svg>
      <Tooltip tip={tip} />
    </div>
  );
}

export interface BarItem { label: string; value: number; color?: string; icon?: string }
export function BarList({ items, total }: { items: BarItem[]; total?: number }) {
  const max = total ?? Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="bars" role="list">
      {items.map((it) => (
        <div className="b-row" key={it.label} role="listitem" title={`${it.label}: ${it.value}`}>
          <span className="b-label">{it.label}</span>
          <div className="b-track"><div className="b-fill" style={{ width: `${(it.value / max) * 100}%`, background: it.color ?? "var(--series)" }} /></div>
          <span className="b-val">{it.value}</span>
        </div>
      ))}
    </div>
  );
}

export const Meter = ({ pct, label }: { pct: number; label: string }) => (
  <div className="meter" role="meter" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={label}><i style={{ width: `${pct}%` }} /></div>
);
