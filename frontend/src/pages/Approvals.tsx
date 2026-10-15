import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Plan } from "../services/api";
import PlanView from "../components/PlanView";
import { Empty, PageHeader, Skeleton } from "../components/Common";

export default function Approvals() {
  const [plans, setPlans] = useState<Plan[] | null>(null);
  const load = useCallback(() => { api<Plan[]>("/plans?status=pending_approval").then(setPlans).catch(() => setPlans([])); }, []);
  useEffect(load, [load]);
  return (
    <>
      <PageHeader title="Approvals" subtitle="Nothing modifies a device until the exact plan is approved here." />
      {!plans ? <Skeleton h={140} /> : plans.length === 0 ? <div className="card"><Empty icon="checkCircle">Nothing is waiting for approval.</Empty></div> :
        plans.map((p) => (<div key={p.id}><p className="muted" style={{ margin: "0 0 6px" }}>For <Link to={`/tasks/${p.task_id}`}>investigation #{p.task_id}</Link></p><PlanView plan={p} onDone={load} /></div>))}
    </>
  );
}
