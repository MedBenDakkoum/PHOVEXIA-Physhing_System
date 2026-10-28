import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import * as authApi from "../api/auth";
import { SESSION_EXPIRED_EVENT, tokenStore } from "../api/client";
import { ApiError } from "../api/errors";
import { useToast } from "./ToastContext";

const AuthContext = createContext(null);

/**
 * status : "loading" (vérification de la session) | "authenticated" | "anonymous" | "offline"
 * user   : { id, email, first_name, last_name, role, date_joined } (GET /api/auth/me/)
 */
export function AuthProvider({ children }) {
  const toast = useToast();
  const [user, setUser] = useState(null);
  const [status, setStatus] = useState(() => (tokenStore.get() ? "loading" : "anonymous"));
  const [bootTick, setBootTick] = useState(0);

  // Restauration de la session au chargement
  useEffect(() => {
    if (!tokenStore.get()) return undefined;
    const ac = new AbortController();
    setStatus("loading");
    authApi
      .getMe(ac.signal)
      .then((me) => {
        if (!me || typeof me !== "object" || !me.role) throw new ApiError("Session invalide", { status: 401 });
        setUser(me);
        setStatus("authenticated");
      })
      .catch((e) => {
        if (e?.name === "AbortError") return;
        // 0 = réseau/TypeError (fetch rejeté) : serveur injoignable, on garde la session
        if (e?.status === 0) {
          setStatus("offline");
          return;
        }
        tokenStore.clear();
        setUser(null);
        setStatus("anonymous");
      });
    return () => ac.abort();
  }, [bootTick]);

  // Le refresh token a expiré, a été révoqué ou le compte a été suspendu
  useEffect(() => {
    const onExpired = () => {
      setUser(null);
      setStatus("anonymous");
      toast.info("Session expirée", "Reconnectez-vous pour continuer.");
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
  }, [toast]);

  const login = useCallback(async ({ email, password }) => {
    const tokens = await authApi.login({ email: email.trim().toLowerCase(), password });
    if (!tokens?.access) throw new ApiError("Session invalide", { status: 401 });
    tokenStore.set(tokens);
    try {
      const me = await authApi.getMe();
      if (!me || typeof me !== "object" || !me.role) throw new ApiError("Session invalide", { status: 401 });
      setUser(me);
      setStatus("authenticated");
      return me;
    } catch (e) {
      tokenStore.clear();
      throw e;
    }
  }, []);

  const register = useCallback(
    async (payload) => {
      await authApi.register({ ...payload, email: payload.email.trim().toLowerCase() });
      // Le backend ne renvoie pas de jetons à l'inscription : on enchaîne avec la connexion.
      return login({ email: payload.email, password: payload.password });
    },
    [login]
  );

  const logout = useCallback(async () => {
    try {
      await authApi.logout(); // blackliste le refresh token côté serveur
    } catch {
      /* même si l'appel échoue, la session locale doit être fermée */
    }
    sessionStorage.setItem("pm.loggedOut", "1");
    tokenStore.clear();
    setUser(null);
    setStatus("anonymous");
  }, []);

  const updateProfile = useCallback(async (payload) => {
    const me = await authApi.updateMe(payload);
    setUser((prev) => ({ ...prev, ...me }));
    return me;
  }, []);

  const refreshUser = useCallback(async () => {
    const me = await authApi.getMe();
    setUser(me);
    return me;
  }, []);

  const retryBoot = useCallback(() => setBootTick((t) => t + 1), []);

  const value = useMemo(
    () => ({
      user,
      status,
      isAuthenticated: status === "authenticated",
      isAdmin: user?.role === "admin",
      isAnalystOrAdmin: user?.role === "admin" || user?.role === "analyst",
      login,
      register,
      logout,
      updateProfile,
      refreshUser,
      retryBoot,
    }),
    [user, status, login, register, logout, updateProfile, refreshUser, retryBoot]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
