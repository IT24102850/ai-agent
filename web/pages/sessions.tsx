import { useEffect, useMemo, useState } from "react";
import { apiGet } from "../lib/api";

type Session = { id: string; name?: string; status: string; created_at: string };

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  useEffect(() => {
    apiGet<{ sessions: Session[] }>("/v1/sessions").then((data) =>
      setSessions(data?.sessions ?? [])
    );
  }, []);
  const visible = useMemo(() => sessions.filter((session) => {
    const matchesSearch = `${session.name || ""} ${session.id}`.toLowerCase().includes(search.toLowerCase());
    return matchesSearch && (status === "all" || session.status === status);
  }), [sessions, search, status]);
  return (
    <>
      <h1>Sessions</h1>
      <label>Search <input aria-label="Search sessions" value={search} onChange={(event) => setSearch(event.target.value)} /></label>{" "}
      <label>Status <select aria-label="Filter session status" value={status} onChange={(event) => setStatus(event.target.value)}>
        <option value="all">All</option><option value="active">Active</option><option value="ended">Ended</option>
      </select></label>
      {visible.length === 0 && <p>No matching sessions.</p>}
      <ul>
        {visible.map((session) => (
          <li key={session.id}>
            <a href={`/sessions/${session.id}/timeline`}>{session.name || session.id}</a>{" "}
            <span aria-label={`Status ${session.status}`}>[{session.status}]</span>
          </li>
        ))}
      </ul>
    </>
  );
}
