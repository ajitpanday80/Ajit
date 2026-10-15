import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Plan } from "../services/api";
import PlanView from "../components/PlanView";

export default function Approvals() {
  const [plans, setPlans] = useState<Plan[]>([]);
  const load = useCallback(() => { api<Plan[]>("/plans?status=pending_approval").then(setPlans).catch(() => undefined); }, []);
  useEffect(load, [load]);
  return (
    <>
      <h2>Pending approvals</h2>
      {plans.length === 0 && <p>Nothing waiting for approval.</p>}
      {plans.map((p) => (<div key={p.id}><p><Link to={`/tasks/${p.task_id}`}>Task #{p.task_id}</Link></p><PlanView plan={p} onDone={load} /></div>))}
    </>
  );
}
