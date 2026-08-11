import {
  Chart,
  Settings,
  BarSeries,
  Axis,
  ScaleType,
  Position,
  DARK_THEME,
} from "@elastic/charts";
import { EuiPanel, EuiTitle, EuiText, EuiSpacer, EuiEmptyPrompt } from "@elastic/eui";

// single measure across categories: one hue, magnitude carried by length
const BAR = "#5b82c2";

const theme = {
  chartMargins: { top: 8, bottom: 4, left: 4, right: 4 },
  barSeriesStyle: { rect: { strokeWidth: 1, stroke: "#1a1a19" } },
};

export default function TopSrcIps({ ips, hours }) {
  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>Top source IPs</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>Most active alert sources, last {hours}.</p>
      </EuiText>
      <EuiSpacer size="s" />
      {ips?.length ? (
        <div style={{ height: 260 }}>
          <Chart>
            <Settings baseTheme={DARK_THEME} theme={theme} rotation={90} />
            <BarSeries
              id="ips"
              name="Alerts"
              xScaleType={ScaleType.Ordinal}
              yScaleType={ScaleType.Linear}
              xAccessor="ip"
              yAccessors={["count"]}
              color={BAR}
              data={ips}
            />
            <Axis id="ip" position={Position.Left} />
            <Axis id="count" position={Position.Bottom} ticks={4} integersOnly />
          </Chart>
        </div>
      ) : (
        <EuiEmptyPrompt
          iconType="globe"
          titleSize="xs"
          title={<h3>No source IPs yet</h3>}
          body={<p>No alerts carrying a source IP in the last {hours}.</p>}
        />
      )}
    </EuiPanel>
  );
}
