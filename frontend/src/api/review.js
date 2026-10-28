import { ENDPOINTS } from "./constants";
import { request, unwrap } from "./client";

export const listReviewQueue = (params = {}, signal) =>
  request(ENDPOINTS.reviewQueue, { params, signal }).then(unwrap);

export const getReview = (id, signal) => request(ENDPOINTS.review(id), { signal }).then(unwrap);

export const decideReview = (id, payload) =>
  request(ENDPOINTS.reviewDecision(id), { method: "POST", body: payload }).then(unwrap);

export const addReviewNote = (id, text) =>
  request(ENDPOINTS.reviewNotes(id), { method: "POST", body: { text } }).then(unwrap);

export const rescanReview = (id) =>
  request(ENDPOINTS.reviewRescan(id), { method: "POST" }).then(unwrap);
