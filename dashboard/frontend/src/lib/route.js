import { useCallback, useEffect, useState } from "react";

// Hash routes: #/<page>?start=now-7d&agent=web-01&ip=1.2.3.4&alert=ai:AbC
// What the console shows lives in the URL, so a copied link reopens the same
// view (page, range, agent, open IP pivot, open alert), back/forward step
// between views, and a reload keeps your place. Defaults are left out.
function parse() {
  const [path, qs = ""] = window.location.hash.replace(/^#\/?/, "").split("?");
  return { page: path || null, ...Object.fromEntries(new URLSearchParams(qs)) };
}

function format({ page, ...params }) {
  const qs = new URLSearchParams(
    Object.entries(params).filter(([, v]) => v != null && v !== "")
  ).toString();
  return `#/${page ?? ""}${qs ? `?${qs}` : ""}`;
}

export function useHashRoute() {
  const [route, setRoute] = useState(parse);

  useEffect(() => {
    const onChange = () => setRoute(parse());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  // patch: keys to set; null removes one. Each change is a history entry.
  const navigate = useCallback((patch) => {
    const next = format({ ...parse(), ...patch });
    if (next !== window.location.hash) window.location.hash = next;
  }, []);

  return [route, navigate];
}
