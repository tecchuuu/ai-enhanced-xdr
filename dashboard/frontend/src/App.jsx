import { useState } from "react";
import {
  EuiHeader,
  EuiHeaderSection,
  EuiHeaderSectionItem,
  EuiHeaderLogo,
  EuiHealth,
  EuiIcon,
  EuiButtonIcon,
  EuiPageTemplate,
  EuiSideNav,
  EuiTextColor,
  EuiToolTip,
  EuiSuperDatePicker,
  EuiSelect,
} from "@elastic/eui";
import { getHealth, getAgents } from "./api";
import { usePolling } from "./lib/usePolling";
import { IpContext } from "./lib/ipContext";
import { useTheme } from "./theme/ThemeProvider";
import IpFlyout from "./components/IpFlyout";
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
    icon: "alert",
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

export default function App() {
  const { colorMode, toggle } = useTheme();
  const [page, setPage] = useState("overview");
  const [connected, setConnected] = useState(null); // null = connecting
  const [updatedAt, setUpdatedAt] = useState(null);
  // the scope every scoped page reads: date-math strings straight from the
  // picker (resolved per fetch, see lib/scope.js) and an agent name ("" = all)
  const [range, setRange] = useState({ start: "now-24h", end: "now" });
  const [agent, setAgent] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [agents, setAgents] = useState([]);
  const [ip, setIp] = useState(null); // the IP pivot flyout, opened from anywhere

  // each page loads and polls its own data; the header only tracks the API
  usePolling(async (isCurrent) => {
    try {
      await getHealth();
      if (!isCurrent()) return;
      setConnected(true);
      setUpdatedAt(new Date());
    } catch {
      if (isCurrent()) setConnected(false);
    }
  }, REFRESH_MS);

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
      onTimeChange={({ start, end, isInvalid }) => !isInvalid && setRange({ start, end })}
      onRefresh={() => setRefreshKey((k) => k + 1)}
      width="auto"
    />,
    <EuiSelect
      key="agent"
      aria-label="Agent"
      options={[
        { value: "", text: "All agents" },
        ...agents.map((a) => ({ value: a.name, text: a.name })),
      ]}
      value={agent}
      onChange={(e) => setAgent(e.target.value)}
    />,
  ];

  const navItems = NAV_GROUPS.map((g) => ({
    id: g.id,
    name: g.name,
    items: g.pages.map((id) => ({
      id,
      name: PAGES[id].title,
      icon: <EuiIcon type={PAGES[id].icon} />,
      onClick: () => setPage(id),
      isSelected: page === id,
    })),
  }));

  const Page = PAGES[page].component;

  return (
    <IpContext.Provider value={setIp}>
      <EuiHeader>
        <EuiHeaderSection>
          <EuiHeaderSectionItem>
            <EuiHeaderLogo iconType="securityApp">AI-XDR</EuiHeaderLogo>
          </EuiHeaderSectionItem>
        </EuiHeaderSection>
        <EuiHeaderSection side="right">
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
      {ip && <IpFlyout ip={ip} onClose={() => setIp(null)} />}
    </IpContext.Provider>
  );
}
