import { ENDPOINTS } from "./constants";
import { apiFetchBlob, request, unwrap } from "./client";
import { ApiError, messageFromResponse } from "./errors";

export const listBlocklist = (params = {}, signal) =>
  request(ENDPOINTS.blocklist, { params, signal }).then(unwrap);

export const addBlocklistEntry = (payload) =>
  request(ENDPOINTS.blocklist, { method: "POST", body: payload }).then(unwrap);

export const removeBlocklistEntry = (id, reason) =>
  request(ENDPOINTS.blocklistEntry(id), { method: "DELETE", body: { reason } }).then(unwrap);

export async function exportBlocklistCsv(signal) {
  const res = await apiFetchBlob(ENDPOINTS.blocklistExport, { signal });
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
