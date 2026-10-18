import { useCallback, useEffect, useState } from "react";
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiDescriptionList,
  EuiBadge,
  EuiButton,
  EuiCallOut,
  EuiLoadingSpinner,
} from "@elastic/eui";
import { getIpEntity } from "../api";
import { fmtTime } from "../lib/format";
import AlertsTable from "./AlertsTable";
import BlockIpModal from "./BlockIpModal";

function BlockStatus({ blocked }) {
  if (!blocked) return "not blocked";
  return (
    <>
      <EuiBadge color={blocked.unblock_unconfirmed ? "warning" : "danger"}>
        {blocked.unblock_unconfirmed ? "unblock unconfirmed" : "blocked"}
      </EuiBadge>{" "}
      since {fmtTime(blocked.since)} on agent {blocked.agent_id} — managed under Response log
    </>
  );
}

// The IP pivot: everything the console has on one source address, all time.
// Opened from any IP link (tables, alert flyout, top-IPs chart, blocked list).
// refreshKey: reload after a triage save or block made in the alert flyout above it.
export default function IpFlyout({ ip, onClose, refreshKey }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [blocking, setBlocking] = useState(false);

  const load = useCallback(
    () =>
      getIpEntity(ip)
        .then((d) => {
          setData(d);
          setError(null);
        })
        .catch((e) => setError(String(e.message ?? e))),
    [ip]
  );

  useEffect(() => {
    setData(null);
  }, [ip]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const stats = data && [
    { title: data.rule_count, description: "Rule alerts (any level)" },
    { title: data.ai_count, description: "AI detections" },
    { title: fmtTime(data.first_seen), description: "First seen" },
    { title: fmtTime(data.last_seen), description: "Last seen" },
  ];
  const shown = data?.alerts.length ?? 0;
  const total = (data?.rule_count ?? 0) + (data?.ai_count ?? 0);

  return (
    <EuiFlyout onClose={onClose} size="l" ownFocus aria-labelledby="ip-flyout-title">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="s">
          <h2 id="ip-flyout-title">{ip}</h2>
        </EuiTitle>
        <EuiSpacer size="xs" />
        <EuiText size="s" color="subdued">
          Everything this console has seen from this address, all time.
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {error && <EuiCallOut title={error} color="danger" iconType="warning" size="s" />}
        {!data && !error && <EuiLoadingSpinner size="l" />}
        {data && (
          <>
            <EuiFlexGroup gutterSize="s" wrap>
              {stats.map((s) => (
                <EuiFlexItem key={s.description} style={{ minWidth: 150 }}>
                  <EuiPanel hasBorder paddingSize="s">
                    <EuiStat
                      title={String(s.title)}
                      description={s.description}
                      titleSize="xs"
                      titleColor="default"
                    />
                  </EuiPanel>
                </EuiFlexItem>
              ))}
            </EuiFlexGroup>
            <EuiSpacer />
            <EuiDescriptionList
              type="column"
              compressed
              listItems={[
                { title: "Block status", description: <BlockStatus blocked={data.blocked} /> },
                {
                  title: "Accounts targeted",
                  description: data.users.length
                    ? data.users.map((u) => `${u.user} (${u.count})`).join(", ")
                    : "—",
                },
                { title: "Agents", description: data.agents.join(", ") || "—" },
              ]}
            />
            <EuiSpacer />
            <EuiTitle size="xxs">
              <h3>Alerts</h3>
            </EuiTitle>
            {shown < total && (
              <EuiText size="xs" color="subdued">
                <p>
                  Latest {shown} of {total} — search the feeds for older ones.
                </p>
              </EuiText>
            )}
            <EuiSpacer size="s" />
            <AlertsTable alerts={data.alerts} />
          </>
        )}
      </EuiFlyoutBody>
      {data && !data.blocked && (
        <EuiFlyoutFooter>
          <EuiFlexGroup justifyContent="flexEnd">
            <EuiFlexItem grow={false}>
              <EuiButton color="danger" iconType="securitySignalDetected" onClick={() => setBlocking(true)}>
                Block {ip}
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlyoutFooter>
      )}
      {blocking && (
        <BlockIpModal
          srcip={ip}
          alertRef={`IP pivot — ${ip}`}
          defaultAgentName={data?.agents?.[0]}
          onClose={() => {
            setBlocking(false);
            load();
          }}
        />
      )}
    </EuiFlyout>
  );
}
