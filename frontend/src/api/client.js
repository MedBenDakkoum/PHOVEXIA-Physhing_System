import { ENDPOINTS } from "./constants.js";

// Same-origin in prod; Vite proxy /api in dev
const BASE = import.meta.env.VITE_API_URL || "/api";

let refreshPromise = null;

function getTokens() {
  try {
    const raw = localStorage.getItem("pm.tokens");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function setTokens(t) {
  if (t) localStorage.setItem("pm.tokens", JSON.stringify(t));
  else localStorage.removeItem("pm.tokens");
}
function clearTokens() {
  localStorage.removeItem("pm.tokens");
}

async function doRefresh() {
  const tokens = getTokens();
  if (!tokens?.refresh) throw new Error("No refresh");
  const r = await fetch(BASE + ENDPOINTS.refresh, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh: tokens.refresh }),
  });
  if (!r.ok) throw new Error("Refresh failed " + r.status);
  const data = await r.json();
  setTokens({ ...tokens, access: data.access, refresh: data.refresh || tokens.refresh });
  return data.access;
}

async function refreshOnce() {
  if (!refreshPromise) refreshPromise = doRefresh().finally(() => { refreshPromise = null; });
  return refreshPromise;
}

export const SESSION_EXPIRED_EVENT = "pm:session_expired";
export { apiFetch as request, clearTokens };
export const tokenStore = { get: getTokens, set: setTokens, clear: clearTokens };
export async function apiFetch(url, opts = {}) {
  const tokens = getTokens();
  const headers = { "Content-Type": "application/json", ...opts.headers };
  if (tokens?.access) headers.Authorization = `Bearer ${tokens.access}`;
  const res = await fetch(BASE + url, { ...opts, headers });
  // 401 -> single refresh once
  if (res.status === 401 && tokens?.refresh && !opts._retry) {
    try {
      await refreshOnce();
      const newTokens = getTokens();
      const retryHeaders = { ...headers, Authorization: `Bearer ${newTokens.access}` };
      const retry = await fetch(BASE + url, { ...opts, headers: retryHeaders, _retry: true });
      if (!retry.ok) {
        if (retry.status === 401) { clearTokens(); window.location.href = "/login"; }
      }
      return handleResponse(retry);
    } catch {
      clearTokens(); window.location.href = "/login"; return handleResponse(res);
    }
  }
  return handleResponse(res);
}

function handleResponse(res) {
  const body = res.headers.get("content-type")?.includes("application/json") ? res.json().catch(() => null) : Promise.resolve(null);
  return body.then(async (data) => {
    const result = { status: res.status, ok: res.ok, data, headers: {} };
    // 429 Retry-After
    const ra = res.headers.get("Retry-After");
    if (ra) result.retryAfter = parseInt(ra, 10) || 0;
    // Errors mapping
    if (!res.ok) {
      if (res.status === 400) result.error = { message: (data?.detail || "Requête invalide") + (data?.field_errors ? " — " + JSON.stringify(data.field_errors) : ""), code: "BAD_REQUEST" };
      else if (res.status === 409) result.error = { message: data?.detail || "Conflit (doublon ou état incohérent)", code: "CONFLICT" };
      else if (res.status === 401) result.error = { message: "Non autorisé — reconnectez-vous", code: "UNAUTHORIZED" };
      else if (res.status === 403) result.error = { message: "Accès interdit", code: "FORBIDDEN" };
      else if (res.status === 404) result.error = { message: "Non trouvé", code: "NOT_FOUND" };
      else if (res.status === 429) result.error = { message: `Quota atteint — réessayez dans ${result.retryAfter || "quelques"} secondes`, code: "TOO_MANY_REQUESTS" };
      else result.error = { message: data?.detail || "Erreur serveur", code: "SERVER_ERROR", status: res.status };
    }
    return result;
  });
}

export function logout() {
  clearTokens();
  // Call logout endpoint best-effort without blocking redirect
  fetch(BASE + ENDPOINTS.logout, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${(getTokens()?.access || "")}` } }).catch(() => null);
  window.location.href = "/login";
}
