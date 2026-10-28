import { ENDPOINTS } from "./constants";
import { request, unwrap } from "./client";

/**
 * GET /api/auth/users/  (admin) -> corps (liste ou paginée), lève ApiError.
 * Filtres : role, is_active (true|false), search (email, first_name, last_name).
 * Le backend ne pagine pas cette liste : on accepte aussi le format paginé par prudence.
 */
export async function listUsers(params = {}, signal) {
  const data = unwrap(await request(ENDPOINTS.users, { params, signal }));
  return Array.isArray(data) ? data : data?.results ?? [];
}

/** POST /api/auth/users/ (admin): create an account and choose its role. */
export const createUser = (payload) => request(ENDPOINTS.users, { method: "POST", body: payload }).then(unwrap);

/** GET /api/auth/users/{id}/ */
export const getUser = (id) => request(ENDPOINTS.user(id)).then(unwrap);

/** PATCH /api/auth/users/{id}/  { first_name?, last_name?, role?, is_active? } */
export const updateUser = (id, payload) => request(ENDPOINTS.user(id), { method: "PATCH", body: payload }).then(unwrap);

/** DELETE /api/auth/users/{id}/ -> 204 : suspend le compte (is_active = false), ne le supprime pas. */
export const suspendUser = (id) => request(ENDPOINTS.user(id), { method: "DELETE" }).then(unwrap);

/** Réactivation : PATCH is_active = true */
export const reactivateUser = (id) => updateUser(id, { is_active: true });
