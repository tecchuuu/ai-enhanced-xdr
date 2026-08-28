import {
  Chart,
  Settings,
  BarSeries,
  Axis,
  ScaleType,
  Position,
} from "@elastic/charts";
import {
  EuiPanel,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiEmptyPrompt,
} from "@elastic/eui";
import { useTheme, usePalette, useChartTheme } from "../theme/ThemeProvider";

export default function TopSrcIps({ ips, hours }) {
  const { baseTheme } = useTheme();
  const p = usePalette();
  const theme = useChartTheme();

  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>Top source IPs</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>Most active alert sources, last {hours}.</p>
      </EuiText>
      <EuiSpacer size="s" />
      <div style={{ height: 260 }}>
        {ips?.length ? (
          <Chart>
            {/* single measure across categories: one hue, magnitude by bar length */}
            <Settings baseTheme={baseTheme} theme={theme} rotation={90} />
            <BarSeries
              id="ips"
              name="Alerts"
              xScaleType={ScaleType.Ordinal}
              yScaleType={ScaleType.Linear}
              xAccessor="ip"
              yAccessors={["count"]}
              color={p.single}
              data={ips}
            />
            <Axis id="ip" position={Position.Left} />
            <Axis
              id="count"
              position={Position.Bottom}
              ticks={4}
              integersOnly
            />
          </Chart>
        ) : (
          <EuiEmptyPrompt
            iconType="globe"
            titleSize="xs"
            title={<h3>No source IPs yet</h3>}
            body={
              <p>
                No alerts carrying a source IP in the last {hours}. Attacks from
                another host will populate this; loopback traffic will not.
              </p>
            }
          />
        )}
      </div>
    </EuiPanel>
  );
}
