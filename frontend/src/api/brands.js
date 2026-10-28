import { ENDPOINTS } from "./constants";
import { request, unwrap } from "./client";

export const listBrands = (params = {}, signal) =>
  request(ENDPOINTS.brands, { params, signal }).then(unwrap);

export const createBrand = (payload) =>
  request(ENDPOINTS.brands, { method: "POST", body: payload }).then(unwrap);

export const updateBrand = (id, payload) =>
  request(ENDPOINTS.brand(id), { method: "PATCH", body: payload }).then(unwrap);
