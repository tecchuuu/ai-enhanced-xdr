import { useCallback, useEffect, useRef } from "react";

// Runs load() now, every `ms` while the tab is visible, on returning to the
// tab, and again whenever `deps` change. load receives isCurrent(): check it
// before setting state, so a slow response for an earlier range (or from a
// page that has since unmounted) can't overwrite a newer one.
// Returns refresh(), for reloading right after an action (e.g. a triage save).
export function usePolling(load, ms, deps = []) {
  const loadRef = useRef(load);
  const gen = useRef(0);

  useEffect(() => {
    loadRef.current = load;
  });

  const refresh = useCallback(() => {
    const mine = gen.current;
    // pages handle their own errors; this only stops a stray rejection
    return Promise.resolve(loadRef.current(() => gen.current === mine)).catch(() => {});
  }, []);

  useEffect(() => {
    gen.current += 1;
    refresh();
    const tick = () => {
      if (!document.hidden) refresh();
    };
    const t = setInterval(tick, ms);
    document.addEventListener("visibilitychange", tick);
    return () => {
      gen.current += 1;
      clearInterval(t);
      document.removeEventListener("visibilitychange", tick);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, refresh, ...deps]);

  return refresh;
}
