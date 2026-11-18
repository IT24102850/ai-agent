import { useEffect, useState } from "react";
import { apiGet, apiPost } from "../lib/api";

type Suite = { id: string; name: string; test_case_ids: string[] };
type Case = { id: string; name: string };

export default function TestSuitesPage() {
  const [suites, setSuites] = useState<Suite[]>([]);
  const [cases, setCases] = useState<Case[]>([]);
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("Regression suite");
  const [runs, setRuns] = useState<any[]>([]);
  const [run, setRun] = useState<any>(null);
  async function refresh() {
    const suiteData = await apiGet<{ test_suites: Suite[] }>("/v1/test-suites");
    setSuites(suiteData?.test_suites ?? []);
    const caseData = await apiGet<{ test_cases: Case[] }>("/v1/test-cases");
    setCases(caseData?.test_cases ?? []);
  }
  useEffect(() => { refresh(); }, []);
  async function createSuite() {
    const ids = cases.map((item) => item.id);
    const suite = await apiPost<Suite>("/v1/test-suites", { name, test_case_ids: ids });
    if (suite) { setSelected(suite.id); await refresh(); }
  }
  async function execute() {
    if (!selected) return;
    const result = await apiPost<any>(`/v1/test-suites/${selected}/runs`, {});
    setRun(result);
    const data = await apiGet<{ suite_runs: any[] }>(`/v1/test-suites/${selected}/runs`);
    setRuns(data?.suite_runs ?? []);
  }
  async function approve(runId: string) {
    await apiPost(`/v1/test-runs/${runId}/approve`, { approved_by: "console" });
    await execute();
  }
  return (
    <>
      <h1>Test suites</h1>
      <label>Suite name <input value={name} onChange={(e) => setName(e.target.value)} /></label>
      <button onClick={createSuite}>Create suite from test cases</button>
      <h2>Suites</h2>
      {suites.map((suite) => <button key={suite.id} onClick={() => setSelected(suite.id)}>{suite.name}</button>)}
      {selected && <><p>Selected: <code>{selected}</code></p><button onClick={execute}>Run suite</button></>}
      {run && <section><h2>Latest run: {run.status}</h2><pre>{JSON.stringify(run.summary, null, 2)}</pre>
        {(run.test_run_ids || []).map((runId: string) => <button key={runId} onClick={() => approve(runId)}>Approve {runId}</button>)}
      </section>}
      <h2>Run history</h2>
      {runs.map((item) => <pre key={item.id}>{item.id}: {item.status}</pre>)}
      <h2>Test cases</h2>
      {cases.map((item) => <div key={item.id}><code>{item.id}</code> {item.name}</div>)}
    </>
  );
}
