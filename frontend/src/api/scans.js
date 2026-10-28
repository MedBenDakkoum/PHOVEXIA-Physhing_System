import { ENDPOINTS } from "./constants";
import { apiFetchBlob, request, unwrap } from "./client";
import { ApiError, messageFromResponse } from "./errors";

export const getScan = (id, signal) => request(ENDPOINTS.scan(id), { signal }).then(unwrap);

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
