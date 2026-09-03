import { useCallback, useEffect, useState } from "react";
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
  EuiText,
  EuiToolTip,
} from "@elastic/eui";
import { getStats, getCombined, getHealth } from "./api";
import { useTheme } from "./theme/ThemeProvider";
import Overview from "./pages/Overview";
import SecurityEvents from "./pages/SecurityEvents";
import AiDetections from "./pages/AiDetections";
import Metrics from "./pages/Metrics";
import ResponseLog from "./pages/ResponseLog";
import Agents from "./pages/Agents";

const REFRESH_MS = 15000;

// Every page carries a one-line description — a bare title reads as unfinished.
const PAGES = {
  overview: {
    title: "Overview",
    icon: "dashboardApp",
    description: "Signature rules and the anomaly model, side by side.",
    component: Overview,
  },
  events: {
    title: "Security events",
    icon: "alert",
    description: "Alerts raised by the Wazuh ruleset, with severity and triage state.",
    component: SecurityEvents,
  },
  ai: {
    title: "AI detections",
    icon: "securitySignalDetected",
    description:
      "Windows the anomaly model scored as deviating from baseline, with their anomaly score.",
    component: AiDetections,
  },
  metrics: {
    title: "Metrics",
    icon: "reportingApp",
    description:
      "Live rule-vs-AI comparison: overlap, false-positive rate, and mean time to resolve.",
    component: Metrics,
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
};

// grouped so the nav reads as three jobs rather than six flat links
const NAV_GROUPS = [
  { id: "grp-detections", name: "Detections", pages: ["overview", "events", "ai"] },
  { id: "grp-analysis", name: "Analysis", pages: ["metrics", "responses"] },
  { id: "grp-system", name: "System", pages: ["agents"] },
];

export default function App() {
  const { colorMode, toggle } = useTheme();
  const [page, setPage] = useState("overview");
  const [stats, setStats] = useState(null);
  const [combined, setCombined] = useState(null);
  const [connected, setConnected] = useState(null); // null = connecting
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState(null);

  const load = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([getStats(), getCombined(200)]);
      setStats(s);
      setCombined(c);
      setConnected(true);
      setUpdatedAt(new Date());
    } catch {
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    getHealth().catch(() => setConnected(false));
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

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
    <>
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

        <EuiPageTemplate.Header
          pageTitle={PAGES[page].title}
          description={
            <EuiText size="s" color="subdued">
              {PAGES[page].description}
            </EuiText>
          }
        />
        <EuiPageTemplate.Section>
          <Page
            stats={stats}
            combined={combined}
            loading={loading}
            onRefresh={load}
          />
        </EuiPageTemplate.Section>
      </EuiPageTemplate>
    </>
  );
}
