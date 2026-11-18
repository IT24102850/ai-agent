import { useEffect, useState } from "react";

export default function SettingsPage() {
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    setKey(window.localStorage.getItem("agentblackbox_api_key") || "");
  }, []);
  function save() {
    window.localStorage.setItem("agentblackbox_api_key", key);
    setSaved(true);
  }
  function clear() {
    window.localStorage.removeItem("agentblackbox_api_key");
    setKey("");
    setSaved(false);
  }
  return (
    <>
      <h1>Settings</h1>
      <h2>API key</h2>
      <label>Key <input type="password" value={key} onChange={(e) => setKey(e.target.value)} /></label>
      <button onClick={save}>Save locally</button>{" "}
      <button onClick={clear}>Clear</button>
      {saved && <p role="status">API key saved in this browser.</p>}
      <p>Browser storage is convenience storage only. Production deployments should inject a server-side secret or use a short-lived enterprise identity integration.</p>
    </>
  );
}
