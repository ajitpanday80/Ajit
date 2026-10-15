import { useEffect, useState } from "react";
import { api, streamTimeline, type TimelineEvent } from "../services/api";
import { Badge, fmt } from "./Common";

/** Live investigation timeline: loads history, then follows new transitions over SSE. */
export default function Timeline({ taskId, onChange }: { taskId: number; onChange?: () => void }) {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  useEffect(() => {
    const ctl = new AbortController();
    let last = 0;
    api<TimelineEvent[]>(`/tasks/${taskId}/timeline`).then((h) => { setEvents(h); last = h.length ? h[h.length - 1].seq : 0; })
      .then(() => streamTimeline(taskId, (e) => {
        if (e.seq <= last) return;
        last = e.seq;
        setEvents((p) => [...p, e]);
        onChange?.();
      }, ctl.signal)).catch(() => undefined);
    return () => ctl.abort();
  }, [taskId]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <ol className="timeline">
      {events.map((e) => (
        <li key={e.seq}><time>{fmt(e.at)}</time> <Badge value={e.to_state} /> <small>{e.actor}</small></li>
      ))}
    </ol>
  );
}
