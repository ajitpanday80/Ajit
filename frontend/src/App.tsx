import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./services/auth";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Investigations from "./pages/Investigations";
import TaskDetail from "./pages/TaskDetail";
import Approvals from "./pages/Approvals";
import Clients from "./pages/Clients";
import Reports from "./pages/Reports";
import Audit from "./pages/Audit";

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <p>Loading…</p>;
  if (!user) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Investigations />} />
        <Route path="tasks/:id" element={<TaskDetail />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="clients" element={<Clients />} />
        <Route path="reports" element={<Reports />} />
        <Route path="audit" element={<Audit />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Route>
    </Routes>
  );
}
