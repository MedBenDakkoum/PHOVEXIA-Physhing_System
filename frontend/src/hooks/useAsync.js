import { useCallback, useEffect, useState } from "react";

/**
 * Exécute fn(signal) au montage et à chaque changement de deps.
 * Annule la requête précédente (AbortController) et expose { data, error, loading, reload }.
 */
export function useAsync(fn, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const ac = new AbortController();
    setState((s) => ({ ...s, loading: true, error: null }));
    Promise.resolve(fn(ac.signal))
      .then((data) => {
        if (!ac.signal.aborted) setState({ data, error: null, loading: false });
      })
      .catch((error) => {
        if (error?.name === "AbortError" || ac.signal.aborted) return;
        setState({ data: null, error, loading: false });
      });
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, reload };
}
