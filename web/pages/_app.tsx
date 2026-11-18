import type { AppProps } from "next/app";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 960, margin: "2rem auto", padding: "0 1rem" }}>
      <nav style={{ display: "flex", gap: "1rem", marginBottom: "2rem" }}>
        <a href="/">AgentBlackbox</a>
        <a href="/sessions">Sessions</a>
        <a href="/policies">Policies</a>
        <a href="/test-suites">Test suites</a>
        <a href="/reports">Reports</a>
        <a href="/settings">Settings</a>
      </nav>
      <Component {...pageProps} />
    </main>
  );
}
