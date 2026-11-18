import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import { apiGet, apiPost } from "../../../lib/api";

type Event = { id: string; event_type: string; sequence: number; hash: string; payload: any };

export default function TimelinePage() {
  const router = useRouter();
  const id = typeof router.query.id === "string" ? router.query.id : "";
  const [events, setEvents] = useState<Event[]>([]);
  const [verification, setVerification] = useState<any>(null);
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (id) apiGet<{ events: Event[] }>(`/v1/sessions/${id}/events`).then((data) => setEvents(data?.events ?? []));
  }, [id]);
  async function verify() {
    setVerification(await apiPost<any>(`/v1/sessions/${id}/verify`, {}));
  }
  async function saveTestCase() {
    const result = await apiPost<any>("/v1/test-cases", { session_id: id, name: `Saved ${id}` });
    setMessage(result ? `Saved test case ${result.id}` : "Could not save test case");
  }
  async function replay() {
    const result = await apiPost<any>(`/v1/sessions/${id}/verify`, {});
    setMessage(result?.valid ? "Replay sandbox verification passed" : "Replay verification unavailable");
  }
  return (
    <>
      <h1>Session timeline</h1><p><code>{id}</code></p>
      <button onClick={verify}>Verify chain</button>{" "}
      <button onClick={saveTestCase}>Save test case</button>{" "}
      <button onClick={replay}>Replay</button>
      {verification && <p role="status">Chain valid: <strong>{String(verification.valid)}</strong></p>}
      {message && <p role="status">{message}</p>}
      <ol>
        {events.map((event) => (
          <li key={event.id}>
            <strong>{event.sequence}. {event.event_type}</strong>{" "}
            {JSON.stringify(event.payload).includes("[REDACTED_") && <mark>Redacted</mark>}
            <div><code>{event.hash}</code></div>
          </li>
        ))}
      </ol>
    </>
  );
}
