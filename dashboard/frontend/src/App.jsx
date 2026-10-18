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
} from "@elastic/eui";
import { getHealth, getAgents, getAlert } from "./api";
import { usePolling } from "./lib/usePolling";
import { useHashRoute } from "./lib/route";
import { NavContext } from "./lib/nav";
import { loadSession } from "./lib/session";
import { useTheme } from "./theme/ThemeProvider";
import IpFlyout from "./components/IpFlyout";
import AlertFlyout from "./components/AlertFlyout";
import SessionModal from "./components/SessionModal";
import Overview from "./pages/Overview";
import SecurityEvents from "./pages/SecurityEvents";
import AiDetections from "./pages/AiDetections";
import Metrics from "./pages/Metrics";
import ResponseLog from "./pages/ResponseLog";
import Agents from "./pages/Agents";
import DetectionSplit from "./pages/DetectionSplit";
import Pipeline from "./pages/Pipeline";

const REFRESH_MS = 15000;

// Every page carries a one-line description — a bare title reads as unfinished.
// scoped pages read the header's time range + agent and show those controls.
const PAGES = {
  overview: {
    title: "Overview",
    icon: "dashboardApp",
    description: "Signature rules and the anomaly model, side by side.",
    component: Overview,
    scoped: true,
  },
  events: {
    title: "Security events",
    icon: "warning",
    description: "Alerts raised by the Wazuh ruleset, with severity and triage state.",
    component: SecurityEvents,
    scoped: true,
  },
  ai: {
    title: "AI detections",
    icon: "securitySignalDetected",
    description:
      "Windows the anomaly model scored as deviating from baseline, with their anomaly score.",
    component: AiDetections,
    scoped: true,
  },
  split: {
    title: "Detection split",
    icon: "timeline",
    description:
      "Rule alerts and AI detections on one timeline, minute by minute — the minutes the ruleset stayed silent stand out.",
    component: DetectionSplit,
    scoped: true,
  },
  metrics: {
    title: "Metrics",
    icon: "reportingApp",
    description:
      "Live rule-vs-AI comparison: overlap, false-positive rate, and mean time to resolve.",
    component: Metrics,
    scoped: true,
  },
  responses: {
    title: "Response log",
    icon: "securitySignalResolved",
    description: "Audit trail of every response action taken from this console.",
    component: ResponseLog,
  },
  agents: {
    title: "Agents",
    icon: "monitoringApp",
    description: "Wazuh agents reporting to the manager, and their connection state.",
    component: Agents,
  },
  pipeline: {
    title: "Pipeline",
    icon: "pipelineApp",
    description:
      "Whether each part of the detection pipeline is alive: OpenSearch, the Wazuh API, every detector, and the explainer.",
    component: Pipeline,
  },
};

// grouped so the nav reads as three jobs rather than a flat list of links
const NAV_GROUPS = [
  { id: "grp-detections", name: "Detections", pages: ["overview", "events", "ai"] },
  { id: "grp-analysis", name: "Analysis", pages: ["split", "metrics", "responses"] },
  { id: "grp-system", name: "System", pages: ["pipeline", "agents"] },
];

const DEFAULT_RANGE = { start: "now-24h", end: "now" };

export default function App() {
  const { colorMode, toggle } = useTheme();
  // page, time range, agent, open IP pivot, open alert: all in the URL
  const [route, navigate] = useHashRoute();
  const page = PAGES[route.page] ? route.page : "overview";
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
  const refreshAll = useCallback(() => setRefreshKey((k) => k + 1), []);

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
      name: PAGES[id].title,
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
          <EuiHeaderSectionItem>
            <EuiHealth
              color={connected == null ? "subdued" : connected ? "success" : "danger"}
            >
              {connected == null
                ? "connecting…"
                : connected
                  ? `connected${updatedAt ? " · updated " + updatedAt.toLocaleTimeString() : ""}`
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
