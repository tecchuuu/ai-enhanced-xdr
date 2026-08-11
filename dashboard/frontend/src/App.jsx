import { useCallback, useEffect, useState } from "react";
import {
  EuiHeader,
  EuiHeaderSection,
  EuiHeaderSectionItem,
  EuiHeaderLogo,
  EuiHealth,
  EuiPageTemplate,
  EuiSideNav,
  EuiText,
} from "@elastic/eui";
import { getStats, getCombined, getHealth } from "./api";
import Overview from "./pages/Overview";
import SecurityEvents from "./pages/SecurityEvents";
import AiDetections from "./pages/AiDetections";
import ResponseLog from "./pages/ResponseLog";
import Agents from "./pages/Agents";

const REFRESH_MS = 15000;

const PAGES = {
  overview: { title: "Overview", component: Overview },
  events: { title: "Security events", component: SecurityEvents },
  ai: { title: "AI detections", component: AiDetections },
  responses: { title: "Response log", component: ResponseLog },
  agents: { title: "Agents", component: Agents },
};

export default function App() {
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

  const navItems = [
    {
      name: "AI-XDR",
      id: "root",
      items: Object.entries(PAGES).map(([id, p]) => ({
        id,
        name: p.title,
        onClick: () => setPage(id),
        isSelected: page === id,
      })),
    },
  ];

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
        </EuiHeaderSection>
      </EuiHeader>

      <EuiPageTemplate panelled grow restrictWidth={false}>
        <EuiPageTemplate.Sidebar sticky minWidth={200}>
          <EuiSideNav items={navItems} />
        </EuiPageTemplate.Sidebar>

        <EuiPageTemplate.Header
          pageTitle={PAGES[page].title}
          description={
            page === "overview" ? (
              <EuiText size="s" color="subdued">
                Signature rules and the anomaly model, side by side.
              </EuiText>
            ) : undefined
          }
        />
        <EuiPageTemplate.Section>
          <Page stats={stats} combined={combined} loading={loading} />
        </EuiPageTemplate.Section>
      </EuiPageTemplate>
    </>
  );
}
