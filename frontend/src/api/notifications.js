import { ENDPOINTS } from "./constants";
import { request, unwrap } from "./client";

export const listNotifications = (params = {}, signal) =>
  request(ENDPOINTS.notifications, { params, signal }).then(unwrap);

export const markNotificationRead = (id) =>
  request(ENDPOINTS.notifyRead(id), { method: "POST" }).then(unwrap);
