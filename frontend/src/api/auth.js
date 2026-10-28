import { ENDPOINTS } from "./constants";
import { request, tokenStore, unwrap } from "./client";

/** POST /api/auth/register/  { email, password, first_name, last_name } -> 201 (corps, lève ApiError) */
export const register = (payload) => request(ENDPOINTS.register, { method: "POST", body: payload, auth: false }).then(unwrap);

/** POST /api/auth/login/  { email, password } -> { access, refresh } (corps, lève ApiError) */
export const login = ({ email, password }) =>
  request(ENDPOINTS.login, { method: "POST", body: { email, password }, auth: false }).then(unwrap);

/** POST /api/auth/logout/  { refresh } -> 204 (blackliste le refresh token) */
export async function logout() {
  const tokens = tokenStore.get();
  if (!tokens?.refresh) return;
  try {
    await request(ENDPOINTS.logout, { method: "POST", body: { refresh: tokens.refresh } }).then(unwrap);
  } catch {
    /* la déconnexion locale doit réussir même si l'API échoue */
  }
}

/** GET /api/auth/me/ -> { id, email, first_name, last_name, role, date_joined } (corps, lève ApiError) */
export const getMe = (signal) => request(ENDPOINTS.me, { signal }).then(unwrap);

/** PATCH /api/auth/me/  { first_name?, last_name? }  (email, rôle : lecture seule) */
export const updateMe = (payload) => request(ENDPOINTS.me, { method: "PATCH", body: payload }).then(unwrap);

/** POST /api/auth/change-password/  { old_password, new_password } -> 204 */
export const changePassword = ({ old_password, new_password }) =>
  request(ENDPOINTS.changePassword, { method: "POST", body: { old_password, new_password } }).then(unwrap);
