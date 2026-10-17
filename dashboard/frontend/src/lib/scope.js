import dateMath from "@elastic/datemath";

// The console's scope: the header's time range (date-math strings straight
// from the picker, e.g. "now-24h") and agent. Resolve the range at fetch time,
// not once, so a relative range keeps sliding forward between polls.
export function scopeParams({ start, end, agent }) {
  return {
    start: dateMath.parse(start)?.toISOString(),
    end: dateMath.parse(end, { roundUp: true })?.toISOString(),
    agent: agent || undefined,
  };
}

// usePolling deps for a loader that reads the scope; refreshKey bumps when the
// picker's refresh button is pressed
export const scopeDeps = (scope) => [scope.start, scope.end, scope.agent, scope.refreshKey];
