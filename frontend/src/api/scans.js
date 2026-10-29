import { ENDPOINTS } from "./constants";
import { apiFetchBlob, request, unwrap } from "./client";
import { ApiError, messageFromResponse } from "./errors";

export const listScans = (params = {}, signal) =>
  request(ENDPOINTS.scans, { params, signal }).then(unwrap);

export const createScan = (url) =>
  request(ENDPOINTS.scans, { method: "POST", body: { url } }).then(unwrap);

export const getScanQuota = (signal) =>
  request(ENDPOINTS.scanQuota, { signal }).then(unwrap);

export const getScan = (id, signal) => request(ENDPOINTS.scan(id), { signal }).then(unwrap);

export const reportScan = (id, payload) =>
  request(ENDPOINTS.scanReport(id), { method: "POST", body: payload }).then(unwrap);

export const quickCheck = (url) =>
  request(ENDPOINTS.quickCheck, { method: "POST", body: { url }, auth: false }).then(unwrap);

export const getQuickCheck = (id, signal) =>
  request(ENDPOINTS.quickCheckDetail(id), { auth: false, signal }).then(unwrap);

export async function getScanScreenshot(id, signal) {
  const res = await apiFetchBlob(ENDPOINTS.scanScreenshot(id), { signal });
  if (res.status === 404) return null;
  if (!res.ok) {
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    throw new ApiError(messageFromResponse(res.status, data), { status: res.status, data });
  }
  return res.blob();
}
