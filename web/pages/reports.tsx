import { useEffect, useState } from "react";
import { API_BASE_URL, apiGet } from "../lib/api";

type Session = { id: string; name?: string };

export default function ReportsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionId, setSessionId] = useState("");
  useEffect(() => {
    apiGet<{ sessions: Session[] }>("/v1/sessions").then((data) => setSessions(data?.sessions ?? []));
  }, []);
  const key = process.env.NEXT_PUBLIC_API_KEY || "";
  const auditUrl = `${API_BASE_URL}/v1/sessions/${sessionId}/audit-report`;
  const pdfUrl = `${API_BASE_URL}/v1/sessions/${sessionId}/report.pdf`;
  return (
    <>
      <h1>Reports</h1>
      <label>Session <select value={sessionId} onChange={(e) => setSessionId(e.target.value)}>
        <option value="">Choose a session</option>
        {sessions.map((session) => <option key={session.id} value={session.id}>{session.name || session.id}</option>)}
      </select></label>
      {sessionId && <>
        <p><a href={auditUrl} download>Generate/download JSON audit report</a></p>
        <p><a href={pdfUrl} download>Generate/download PDF report</a></p>
        <p>PDF rendering requires the optional PDF dependency.</p>
        <p><code>API key: {key ? "configured" : "not configured"}</code></p>
      </>}
    </>
  );
}
