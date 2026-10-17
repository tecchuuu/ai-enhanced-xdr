import { useState } from "react";
import { EuiCallOut, EuiSpacer } from "@elastic/eui";
import { getPipelineStatus } from "../api";
import { usePolling } from "../lib/usePolling";
import { fmtAgo } from "../lib/format";

const DAY = 86400;

// Says, above the numbers, when a quiet AI side is the pipeline's doing rather
// than the network's: a detector still warming up, or one that has gone silent.
// A detector silent for over a day is treated as deliberately stopped (the web
// lane isn't always run) and left to the Pipeline page.
export default function PipelineNotice() {
  const [consumers, setConsumers] = useState([]);

  usePolling(async (isCurrent) => {
    try {
      const s = await getPipelineStatus();
      if (isCurrent()) setConsumers(s.consumers);
    } catch {
      /* the header already reports an unreachable API */
    }
  }, 30000);

  const silent = consumers.filter((c) => c.stale && c.age_seconds != null && c.age_seconds < DAY);
  const warming = consumers.filter((c) => !c.stale && c.state === "warming_up");
  if (!silent.length && !warming.length) return null;

  return (
    <>
      {silent.map((c) => (
        <EuiCallOut
          key={c.consumer}
          size="s"
          color="warning"
          iconType="warning"
          title={`${c.consumer} stopped reporting ${fmtAgo(c.last_heartbeat)} — its AI detections may be missing from this view. See System → Pipeline.`}
        />
      ))}
      {warming.map((c) => (
        <EuiCallOut
          key={c.consumer}
          size="s"
          color="primary"
          iconType="clock"
          title={`${c.consumer} is warming up (${c.windows_buffered}/${c.min_windows} windows) — it starts scoring once it has enough history.`}
        />
      ))}
      <EuiSpacer size="m" />
    </>
  );
}
