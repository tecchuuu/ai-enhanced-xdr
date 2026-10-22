import { useState } from "react";
import { usePolling } from "./usePolling";
import { scopeParams, scopeDeps } from "./scope";

const FIRST_VIEW = {
  pageIndex: 0,
  pageSize: 25,
  sort: { field: "timestamp", direction: "desc" },
  triageShown: [],
};

// One page of a feed (/api/alerts/rule or /ai), polled. The table's choices —
// page, page size, sort, review states — go to the server, so every alert in
// the range is reachable and the counts cover all of them. A new filter or
// scope starts again from page 1. Returns what AlertsTable's `server` prop
// takes, plus the raw response and any error.
export function usePagedFeed(fetcher, params, scope) {
  const [view, setView] = useState(FIRST_VIEW);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  // derived reset: the filters or the scope changed since the last render
  const filterKey = JSON.stringify([params, scope.start, scope.end, scope.agent]);
  const [lastKey, setLastKey] = useState(filterKey);
  if (lastKey !== filterKey) {
    setLastKey(filterKey);
    setView((v) => ({ ...v, pageIndex: 0 }));
    setData(null);
  }

  usePolling(
    async (isCurrent) => {
      try {
        const d = await fetcher({
          ...params,
          ...scopeParams(scope),
          limit: view.pageSize,
          offset: view.pageIndex * view.pageSize,
          sort: view.sort.field,
          order: view.sort.direction,
          triage: view.triageShown.join(","),
        });
        if (!isCurrent()) return;
        setData(d);
        setError(null);
      } catch (e) {
        if (isCurrent()) setError(String(e.message ?? e));
      }
    },
    15000,
    [filterKey, view, ...scopeDeps(scope)]
  );

  return {
    data,
    error,
    server: {
      ...view,
      total: data?.count ?? 0,
      triageCounts: data?.triage_counts,
      onChange: (patch) => setView((v) => ({ ...v, ...patch })),
    },
  };
}
