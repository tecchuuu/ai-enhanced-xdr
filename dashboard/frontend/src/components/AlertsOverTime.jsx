import {
  Chart,
  Settings,
  BarSeries,
  Axis,
  ScaleType,
  Position,
  DARK_THEME,
  niceTimeFormatter,
} from "@elastic/charts";
import { EuiPanel, EuiTitle, EuiText, EuiSpacer, EuiEmptyPrompt } from "@elastic/eui";
import { COLOR_RULE, COLOR_AI } from "./badges";

// theme tweaks per mark spec: thin bars separated by a surface-colored stroke
const theme = {
  chartMargins: { top: 8, bottom: 4, left: 4, right: 4 },
  barSeriesStyle: { rect: { strokeWidth: 1, stroke: "#1a1a19" } },
  scales: { barsPadding: 0.25 },
};

export default function AlertsOverTime({ buckets, hours }) {
  const hasData = buckets?.some((b) => b.rule || b.ai);
  const domain =
    buckets?.length > 1
      ? [buckets[0].time, buckets[buckets.length - 1].time]
      : [Date.now() - 864e5, Date.now()];

  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>Alerts over time</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>
          Rule alerts (level 10+) and AI detections per interval, last {hours}. Teal with
          no orange beside it = the model caught something the ruleset stayed silent on.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {hasData ? (
        <div style={{ height: 260 }}>
          <Chart>
            <Settings baseTheme={DARK_THEME} theme={theme} showLegend legendPosition={Position.Bottom} />
            <BarSeries
              id="rule"
              name="Rule alerts"
              xScaleType={ScaleType.Time}
              yScaleType={ScaleType.Linear}
              xAccessor="time"
              yAccessors={["rule"]}
              stackAccessors={["time"]}
              color={COLOR_RULE}
              data={buckets}
            />
            <BarSeries
              id="ai"
              name="AI detections"
              xScaleType={ScaleType.Time}
              yScaleType={ScaleType.Linear}
              xAccessor="time"
              yAccessors={["ai"]}
              stackAccessors={["time"]}
              color={COLOR_AI}
              data={buckets}
            />
            <Axis id="x" position={Position.Bottom} tickFormat={niceTimeFormatter(domain)} />
            <Axis id="y" position={Position.Left} ticks={4} integersOnly />
          </Chart>
        </div>
      ) : (
        <EuiEmptyPrompt
          iconType="visBarVerticalStacked"
          titleSize="xs"
          title={<h3>No alerts in this window</h3>}
          body={<p>Nothing at level 10+ and no AI detections in the last {hours}. Generate some traffic and this fills in.</p>}
        />
      )}
    </EuiPanel>
  );
}
