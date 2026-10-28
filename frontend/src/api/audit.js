import { ENDPOINTS } from "./constants";
import { request, unwrap } from "./client";

/**
 * GET /api/audit/logs/  (admin) -> { count, next, previous, results: [...] }
 * Corps de la réponse, lève ApiError en cas d'échec.
 * Filtres : user (id), user_email (contient), action, date_from, date_to (YYYY-MM-DD)
 * Pagination : page, page_size (max 100)
 */
export const listAuditLogs = (params = {}, signal) => request(ENDPOINTS.auditLogs, { params, signal }).then(unwrap);

/** GET /api/audit/logs/{id}/ */
export const getAuditLog = (id) => request(ENDPOINTS.auditLog(id)).then(unwrap);
