import { useCallback, useEffect, useMemo, useState } from "react";
import {
  EuiHeader,
  EuiHeaderSection,
  EuiHeaderSectionItem,
  EuiHeaderLogo,
  EuiHealth,
  EuiIcon,
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiPageTemplate,
  EuiSideNav,
  EuiTextColor,
  EuiToolTip,
  EuiSuperDatePicker,
  EuiSelect,
  EuiFlyout,
  EuiFlyoutBody,
  EuiCallOut,
  EuiNotificationBadge,
} from "@elastic/eui";
import { getHealth, getAgents, getAlert, getPipelineStatus, getQueue } from "./api";
import { usePolling } from "./lib/usePolling";
import { useHashRoute } from "./lib/route";
import { NavContext } from "./lib/nav";
import { loadSession } from "./lib/session";
import { useTheme } from "./theme/ThemeProvider";
import IpFlyout from "./components/IpFlyout";
import AlertFlyout from "./components/AlertFlyout";
import SessionModal from "./components/SessionModal";
import Overview from "./pages/Overview";
import AlertQueue from "./pages/AlertQueue";
import WazuhAlerts from "./pages/WazuhAlerts";
import AiDetections from "./pages/AiDetections";
import RulesVsAi from "./pages/RulesVsAi";
import ResponseLog from "./pages/ResponseLog";
import Agents from "./pages/Agents";
import Pipeline from "./pages/Pipeline";

const REFRESH_MS = 15000;
const DAY = 86400;

// Every page carries a one-line description — a bare title reads as unfinished.
// scoped pages read the header's time range + agent and show those controls.
// Words are the analyst's, not the code's: an "alert" is what a rule raised
// (an event is any log line), and the AI flags "minutes", not "windows".
const PAGES = {
  overview: {
    title: "Overview",
    icon: "dashboardApp",
    description: "Wazuh's rule alerts and the AI's detections, side by side.",
    component: Overview,
    scoped: true,
  },
  // where an analyst works: not tied to the time picker (see AlertQueue)
  queue: {
    title: "Alert queue",
    icon: "bell",
    description:
      "Alerts that still need a decision — most severe first, and within a severity the longest-waiting first.",
    component: AlertQueue,
  },
  events: {
    title: "Wazuh alerts",
    icon: "warning",
    description: "Alerts raised by Wazuh's detection rules, with severity and review status.",
    component: WazuhAlerts,
    scoped: true,
  },
  ai: {
    title: "AI detections",
    icon: "securitySignalDetected",
    description:
      "Minutes of activity the AI models flagged as unusual compared with normal activity.",
    component: AiDetections,
    scoped: true,
  },
  split: {
    title: "Rules vs AI",
    icon: "timeline",
    description:
      "What the Wazuh rules raised next to what the AI flagged, minute by minute, with the review results.",
    component: RulesVsAi,
    scoped: true,
  },
  responses: {
    title: "Response log",
    icon: "securitySignalResolved",
    description: "Blocked IPs, and every block or unblock taken from this console.",
    component: ResponseLog,
  },
  agents: {
    title: "Agents",
    icon: "monitoringApp",
    description: "The Wazuh agents sending logs to the manager, and whether they are connected.",
    component: Agents,
  },
  pipeline: {
    title: "Pipeline",
    icon: "pipelineApp",
    description:
      "Whether each part of the system is working: the alert store, the Wazuh manager, every detector, and the AI assistant.",
    component: Pipeline,
  },
};
// old links: the Metrics page was merged into Rules vs AI
const PAGE_ALIASES = { metrics: "split" };

// grouped so the nav reads as three jobs rather than a flat list of links.
// Overview first, the work queue right after it — the usual SIEM order
// (QRadar: Dashboard, Offenses; Sentinel: Overview, Incidents).
const NAV_GROUPS = [
  { id: "grp-detections", name: "Detections", pages: ["overview", "queue", "events", "ai"] },
  { id: "grp-analysis", name: "Analysis", pages: ["split", "responses"] },
  { id: "grp-system", name: "System", pages: ["pipeline", "agents"] },
];

const DEFAULT_RANGE = { start: "now-24h", end: "now" };

// The detectors' state, once, in the header — instead of a warning banner on
// every page. A detector silent for over a day is treated as deliberately
// stopped (a standby, or a lane not in use) and left to the Pipeline page.
function detectorSummary(consumers) {
  if (consumers == null) return null;
  const silent = consumers.filter((c) => c.stale && c.age_seconds != null && c.age_seconds < DAY);
  const warming = consumers.filter((c) => !c.stale && c.state === "warming_up");
  const names = (cs) => cs.map((c) => c.consumer).join(", ");
  if (!consumers.length) return { color: "subdued", text: "no detectors reporting", tip: "No detector has checked in yet." };
  if (silent.length)
    return {
      color: "warning",
      text: `${silent.length} detector${silent.length > 1 ? "s" : ""} not reporting`,
      tip: `${names(silent)} stopped checking in — AI detections from ${silent.length > 1 ? "them" : "it"} may be missing.`,
    };
  if (warming.length)
    return {
      color: "primary",
      text: "detectors warming up",
      tip: `${names(warming)} collecting their first minutes of activity before flagging.`,
    };
  return { color: "success", text: "detectors running", tip: "Every detector checked in recently." };
}

export default function App() {
  const { colorMode, toggle } = useTheme();
  // page, time range, agent, open IP pivot, open alert: all in the URL
  const [route, navigate] = useHashRoute();
  const routed = PAGE_ALIASES[route.page] ?? route.page;
  const page = PAGES[routed] ? routed : "overview";
  // the scope every scoped page reads: date-math strings straight from the
  // picker (resolved per fetch, see lib/scope.js) and an agent name ("" = all)
  const range = { start: route.start ?? DEFAULT_RANGE.start, end: route.end ?? DEFAULT_RANGE.end };
  const agent = route.agent ?? "";

  const [connected, setConnected] = useState(null); // null = connecting
  const [updatedAt, setUpdatedAt] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [agents, setAgents] = useState([]);
  const [keyRequired, setKeyRequired] = useState(false);
  const [analyst, setAnalyst] = useState(() => loadSession().analyst ?? "");
  const [sessionPrompt, setSessionPrompt] = useState(null); // null | { rejected }
  const [alertState, setAlertState] = useState(null); // { id, alert?, error? }
  const [consumers, setConsumers] = useState(null);
  const refreshAll = useCallback(() => setRefreshKey((k) => k + 1), []);

  usePolling(async (isCurrent) => {
    try {
      const s = await getPipelineStatus();
      if (isCurrent()) setConsumers(s.consumers);
    } catch {
      /* the connection indicator already reports an unreachable API */
    }
  }, 30000);
  const detectors = detectorSummary(consumers);

  // the queue's count beside its menu entry, so open urgent work shows on every
  // page: critical + high when there are any, otherwise everything still open
  const [queueCounts, setQueueCounts] = useState(null);
  usePolling(
    async (isCurrent) => {
      try {
        const q = await getQueue({ limit: 0 });
        if (isCurrent()) setQueueCounts(q);
      } catch {
        /* the connection indicator already reports an unreachable API */
      }
    },
    30000,
    [refreshKey]
  );
  const urgent = (queueCounts?.severity?.critical ?? 0) + (queueCounts?.severity?.high ?? 0);
  const queueBadge = urgent ? (
    <EuiNotificationBadge color="accent" title={`${urgent} critical or high alerts open`}>
      {urgent}
    </EuiNotificationBadge>
  ) : queueCounts?.count ? (
    <EuiNotificationBadge color="subdued" title={`${queueCounts.count} alerts open`}>
      {queueCounts.count}
    </EuiNotificationBadge>
  ) : null;

  // each page loads and polls its own data; the header only tracks the API
  usePolling(async (isCurrent) => {
    try {
      const h = await getHealth();
      if (!isCurrent()) return;
      setConnected(true);
      setUpdatedAt(new Date());
      setKeyRequired(Boolean(h.auth_required));
      if (h.auth_required && !loadSession().apiKey) setSessionPrompt((p) => p ?? {});
    } catch {
      if (isCurrent()) setConnected(false);
    }
  }, REFRESH_MS);

  // any call the API refused for a missing/wrong key asks for it (api.js)
  useEffect(() => {
    const onUnauthorized = () => setSessionPrompt({ rejected: true });
    window.addEventListener("aixdr:unauthorized", onUnauthorized);
    return () => window.removeEventListener("aixdr:unauthorized", onUnauthorized);
  }, []);

  // The alert flyout. A click hands over the row (shown at once); the alert is
  // then (re)fetched by id, which is also how a pasted link opens it, and how
  // it picks up a triage save, a block or a new explanation (refreshKey).
  useEffect(() => {
    const id = route.alert;
    if (!id) return;
    let alive = true;
    getAlert(id)
      .then((a) => alive && setAlertState({ id, alert: a }))
      .catch(
        (e) =>
          alive &&
          setAlertState((cur) =>
            cur?.id === id && cur.alert ? cur : { id, error: String(e.message ?? e) }
          )
      );
    return () => {
      alive = false;
    };
  }, [route.alert, refreshKey]);

  const nav = useMemo(
    () => ({
      openIp: (ip) => navigate({ ip }),
      openAlert: (a) => {
        setAlertState({ id: a.id, alert: a });
        navigate({ alert: a.id });
      },
      goto: navigate,
    }),
    [navigate]
  );
  const openAlert = route.alert && alertState?.id === route.alert ? alertState : null;

  // agent list for the selector; empty (just "All agents") while the Wazuh API is down
  usePolling(async (isCurrent) => {
    try {
      const { agents } = await getAgents();
      if (isCurrent()) setAgents(agents);
    } catch {
      /* keep the last list */
    }
  }, 60000);

  const scope = { ...range, agent, refreshKey };
  const scopeControls = [
    <EuiSuperDatePicker
      key="time"
      start={range.start}
      end={range.end}
      onTimeChange={({ start, end, isInvalid }) =>
        !isInvalid &&
        navigate({
          start: start === DEFAULT_RANGE.start ? null : start,
          end: end === DEFAULT_RANGE.end ? null : end,
        })
      }
      onRefresh={refreshAll}
      width="auto"
    />,
    <EuiSelect
      key="agent"
      aria-label="Agent"
      options={[
        { value: "", text: "All agents" },
        ...agents.map((a) => ({ value: a.name, text: a.name })),
        // an agent from a link that the Wazuh API doesn't list (API down, or retired)
        ...(agent && !agents.some((a) => a.name === agent) ? [{ value: agent, text: agent }] : []),
      ]}
      value={agent}
      onChange={(e) => navigate({ agent: e.target.value || null })}
    />,
  ];

  const navItems = NAV_GROUPS.map((g) => ({
    id: g.id,
    name: g.name,
    items: g.pages.map((id) => ({
      id,
      name:
        id === "queue" && queueBadge ? (
          <>
            {PAGES[id].title} {queueBadge}
          </>
        ) : (
          PAGES[id].title
        ),
      icon: <EuiIcon type={PAGES[id].icon} />,
      onClick: () => navigate({ page: id, alert: null, ip: null }),
      isSelected: page === id,
    })),
  }));

  const Page = PAGES[page].component;

  return (
    <NavContext.Provider value={nav}>
      <EuiHeader>
        <EuiHeaderSection>
          <EuiHeaderSectionItem>
            <EuiHeaderLogo iconType="securityApp">AI-XDR</EuiHeaderLogo>
          </EuiHeaderSectionItem>
        </EuiHeaderSection>
        <EuiHeaderSection side="right">
          <EuiHeaderSectionItem>
            <EuiToolTip content="Recorded on blocks, unblocks and triage changes">
              <EuiButtonEmpty
                size="xs"
                iconType="user"
                color="text"
                onClick={() => setSessionPrompt({})}
              >
                {analyst || "Set analyst name"}
              </EuiButtonEmpty>
            </EuiToolTip>
          </EuiHeaderSectionItem>
          {detectors && (
            <EuiHeaderSectionItem>
              <EuiToolTip content={`${detectors.tip} Open the Pipeline page for details.`}>
                <EuiButtonEmpty
                  size="xs"
                  color="text"
                  onClick={() => navigate({ page: "pipeline", alert: null, ip: null })}
                >
                  <EuiHealth color={detectors.color}>{detectors.text}</EuiHealth>
                </EuiButtonEmpty>
              </EuiToolTip>
            </EuiHeaderSectionItem>
          )}
          <EuiHeaderSectionItem>
            <EuiHealth
              color={connected == null ? "subdued" : connected ? "success" : "danger"}
            >
              {connected == null
                ? "connecting…"
                : connected
                  ? `connected${updatedAt ? " · updated " + updatedAt.toLocaleTimeString([], { hour12: false }) : ""}`
                  : "API unreachable"}
            </EuiHealth>
          </EuiHeaderSectionItem>
          <EuiHeaderSectionItem>
            <EuiToolTip
              content={colorMode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            >
              <EuiButtonIcon
                aria-label={
                  colorMode === "dark" ? "Switch to light mode" : "Switch to dark mode"
                }
                iconType={colorMode === "dark" ? "sun" : "moon"}
                color="text"
                onClick={toggle}
              />
            </EuiToolTip>
          </EuiHeaderSectionItem>
        </EuiHeaderSection>
      </EuiHeader>

      <EuiPageTemplate panelled grow restrictWidth={false}>
        <EuiPageTemplate.Sidebar sticky minWidth={200}>
          <EuiSideNav items={navItems} />
        </EuiPageTemplate.Sidebar>

        {/* EUI already wraps the description in a <p>, so it must be inline */}
        <EuiPageTemplate.Header
          pageTitle={PAGES[page].title}
          description={<EuiTextColor color="subdued">{PAGES[page].description}</EuiTextColor>}
          rightSideItems={PAGES[page].scoped ? scopeControls : undefined}
        />
        <EuiPageTemplate.Section>
          <Page scope={scope} />
        </EuiPageTemplate.Section>
      </EuiPageTemplate>

      {/* rendered in this order so an alert opened from the IP pivot sits on top */}
      {route.ip && (
        <IpFlyout ip={route.ip} refreshKey={refreshKey} onClose={() => navigate({ ip: null })} />
      )}
      {openAlert?.alert && (
        <AlertFlyout
          alert={openAlert.alert}
          onClose={() => navigate({ alert: null })}
          onRefresh={refreshAll}
        />
      )}
      {openAlert?.error && !openAlert.alert && (
        <EuiFlyout size="s" onClose={() => navigate({ alert: null })} aria-label="Alert not found">
          <EuiFlyoutBody>
            <EuiCallOut
              title={`Couldn't open alert ${openAlert.id}`}
              color="danger"
              iconType="warning"
            >
              <p>{openAlert.error}</p>
            </EuiCallOut>
          </EuiFlyoutBody>
        </EuiFlyout>
      )}
      {sessionPrompt && (
        <SessionModal
          keyRequired={keyRequired || sessionPrompt.rejected}
          rejected={sessionPrompt.rejected}
          onClose={(saved) => {
            setSessionPrompt(null);
            if (saved) {
              setAnalyst(loadSession().analyst ?? "");
              refreshAll();
            }
          }}
        />
      )}
    </NavContext.Provider>
  );
}
