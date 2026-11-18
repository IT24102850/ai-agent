import { useEffect, useState } from "react";
import { apiGet, apiPost } from "../lib/api";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [context, setContext] = useState("{}");
  const [result, setResult] = useState<any>(null);
  useEffect(() => {
    apiGet<{ policies: any[] }>("/v1/policies").then((data) => setPolicies(data?.policies ?? []));
  }, []);
  async function dryRun() {
    try { setResult(await apiPost<any>("/v1/policies/evaluate", { context: JSON.parse(context) })); }
    catch { setResult({ error: "Invalid JSON" }); }
  }
  return (
    <>
      <h1>Policies</h1>
      <h2>Dry run</h2>
      <textarea aria-label="Policy context JSON" rows={8} value={context} onChange={(e) => setContext(e.target.value)} />
      <br /><button onClick={dryRun}>Evaluate</button>
      {result && <pre role="status">{JSON.stringify(result, null, 2)}</pre>}
      <h2>Loaded rules</h2>
      {policies.map((policy, index) => <pre key={index}>{JSON.stringify(policy, null, 2)}</pre>)}
    </>
  );
}
