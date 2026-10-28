import { ENDPOINTS } from "./constants";
import { request, unwrap } from "./client";

export const getAdminDashboard = (params = {}, signal) =>
  request(ENDPOINTS.adminDashboard, { params, signal }).then(unwrap);

export const getAdminSettings = (signal) =>
  request(ENDPOINTS.adminSettings, { signal }).then(unwrap);

export const updateAdminSettings = (payload) =>
  request(ENDPOINTS.adminSettings, { method: "PATCH", body: payload }).then(unwrap);

export const listAdminModels = (params = {}, signal) =>
  request(ENDPOINTS.adminModels, { params, signal }).then(unwrap);

export const createAdminModel = (payload) =>
  request(ENDPOINTS.adminModels, { method: "POST", body: payload }).then(unwrap);

export const activateAdminModel = (id) =>
  request(ENDPOINTS.adminModelActivate(id), { method: "POST" }).then(unwrap);

export const rollbackAdminModel = () =>
  request(ENDPOINTS.adminModelRollback, { method: "POST" }).then(unwrap);

export const compareAdminModels = (ids, signal) =>
  request(ENDPOINTS.adminModelCompare, { params: { ids: ids.join(",") }, signal }).then(unwrap);

export const getAdminHealth = (signal) =>
  request(ENDPOINTS.adminHealth, { signal }).then(unwrap);

export const listAdminApiKeys = (params = {}, signal) =>
  request(ENDPOINTS.adminApiKeys, { params, signal }).then(unwrap);

export const createAdminApiKey = (payload) =>
  request(ENDPOINTS.adminApiKeys, { method: "POST", body: payload }).then(unwrap);

export const revokeAdminApiKey = (id) =>
  request(ENDPOINTS.adminApiKey(id), { method: "DELETE" }).then(unwrap);
