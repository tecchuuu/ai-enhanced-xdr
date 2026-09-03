import {
  Chart,
  Settings,
  BarSeries,
  Axis,
  ScaleType,
  Position,
  niceTimeFormatter,
} from "@elastic/charts";
import {
  EuiPanel,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiEmptyPrompt,
} from "@elastic/eui";
import { useTheme, usePalette, useChartTheme } from "../theme/ThemeProvider";

export default function AlertsOverTime({ buckets, hours }) {
  const { baseTheme } = useTheme();
  const p = usePalette();
  const theme = useChartTheme();

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
          Rule alerts (level 10+) and AI detections per interval, last {hours}.
          A teal bar with no orange beside it = the model caught something the
          ruleset stayed silent on.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <div style={{ height: 260 }}>
        {hasData ? (
          <Chart>
            <Settings
              baseTheme={baseTheme}
              theme={theme}
              showLegend
              legendPosition={Position.Bottom}
            />
            <BarSeries
              id="rule"
              name="Rule alerts"
              xScaleType={ScaleType.Time}
              yScaleType={ScaleType.Linear}
              xAccessor="time"
              yAccessors={["rule"]}
              stackAccessors={["time"]}
              color={p.rule}
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
              color={p.ai}
              data={buckets}
            />
            <Axis
              id="x"
              position={Position.Bottom}
              tickFormat={niceTimeFormatter(domain)}
            />
            <Axis id="y" position={Position.Left} ticks={4} integersOnly />
          </Chart>
        ) : (
          <EuiEmptyPrompt
            iconType="visBarVertical"
            titleSize="xs"
            title={<h3>No alerts in this window</h3>}
            body={
              <p>
                Nothing at level 10+ and no AI detections in the last {hours}.
                Generate some traffic, or widen the time range.
              </p>
            }
          />
        )}
      </div>
    </EuiPanel>
  );
}
