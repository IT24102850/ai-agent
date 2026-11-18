export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

function apiKey(): string {
  if (typeof window !== "undefined") {
    return window.localStorage.getItem("agentblackbox_api_key") ||
      process.env.NEXT_PUBLIC_API_KEY || "";
  }
  return process.env.NEXT_PUBLIC_API_KEY || "";
}

export async function apiGet<T>(path: string): Promise<T | null> {
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { "X-API-Key": apiKey() },
      cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

export async function apiPost<T>(path: string, body: unknown = {}): Promise<T | null> {
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey(),
      },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}
