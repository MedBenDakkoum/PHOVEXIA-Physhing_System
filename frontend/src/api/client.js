import { ENDPOINTS } from "./constants";
import { ApiError, messageFromResponse } from "./errors";

const BASE = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");
const STORAGE_KEY = "pm.tokens";

/* ---------------------------------------------------------------- tokens */
export const tokenStore = {
  get() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY)) || null;
    } catch {
      return null;
    }
  },
  set(tokens) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ access: tokens.access, refresh: tokens.refresh }));
  },
  clear() {
    localStorage.removeItem(STORAGE_KEY);
  },
};

export const SESSION_EXPIRED_EVENT = "pm:session-expired";

/* --------------------------------------------------------------- helpers */
function buildUrl(path, params) {
  const url = `${BASE}${path}`;
  if (!params) return url;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    qs.append(k, String(v));
  }
  const s = qs.toString();
  return s ? `${url}?${s}` : url;
}

async function parseBody(res) {
  if (res.status === 204) return null;
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null; // page HTML d'erreur (DEBUG Django) ou texte brut
  }
}

async function rawFetch(path, { method = "GET", body, params, token, signal } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(buildUrl(path, params), {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (e) {
    if (e?.name === "AbortError") throw e;
    throw new ApiError(messageFromResponse(0, null), { status: 0 });
  }
  const data = await parseBody(res);
  if (!res.ok) {
    const retryAfter = Number(res.headers.get("Retry-After")) || null;
    throw new ApiError(messageFromResponse(res.status, data), { status: res.status, data, retryAfter });
  }
  return data;
}

/* --------------------------------------------------------------- refresh */
// ROTATE_REFRESH_TOKENS + BLACKLIST_AFTER_ROTATION : un refresh token ne sert qu'une fois.
// Les rafraîchissements simultanés sont donc fusionnés en un seul appel.
let refreshing = null;

export function refreshAccessToken() {
  if (!refreshing) {
    refreshing = (async () => {
      const tokens = tokenStore.get();
      if (!tokens?.refresh) throw new ApiError("Session expirée.", { status: 401 });
      try {
        const data = await rawFetch(ENDPOINTS.refresh, { method: "POST", body: { refresh: tokens.refresh } });
        tokenStore.set({ access: data.access, refresh: data.refresh || tokens.refresh });
        return data.access;
      } catch (e) {
        if (e instanceof ApiError && e.status === 0) throw e; // réseau coupé : on garde la session
        tokenStore.clear();
        window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
        throw e;
      }
    })().finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

/* --------------------------------------------------------------- request */
/**
 * Appel d'API. Ajoute le Bearer, rafraîchit le token sur 401 puis rejoue la requête.
 * options : { method, body, params, auth = true, signal }
 */
export async function request(path, { auth = true, ...opts } = {}) {
  if (!auth) return rawFetch(path, opts);

  const tokens = tokenStore.get();
  if (!tokens?.access) {
    if (tokens?.refresh) {
      const access = await refreshAccessToken();
      return rawFetch(path, { ...opts, token: access });
    }
    throw new ApiError("Vous devez être connecté.", { status: 401 });
  }
  try {
    return await rawFetch(path, { ...opts, token: tokens.access });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401 && tokens.refresh) {
      const access = await refreshAccessToken();
      return rawFetch(path, { ...opts, token: access });
    }
    throw e;
  }
}
