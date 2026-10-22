import {
  Chart,
  Settings,
  BarSeries,
  Axis,
  ScaleType,
  Position,
  niceTimeFormatter,
} from "@elastic/charts";
import { EuiPanel, EuiSpacer, EuiEmptyPrompt } from "@elastic/eui";
import { useTheme, usePalette, useChartTheme } from "../theme/ThemeProvider";
import PanelTitle from "./PanelTitle";

// buckets/interval from /api/alerts/histogram; from/to (ms) are the range it
// was asked for, so the axis spans the selected range even when it's sparse
export default function AlertsOverTime({ buckets, interval, from, to }) {
  const { baseTheme } = useTheme();
  const p = usePalette();
  const theme = useChartTheme();

  const hasData = buckets?.some((b) => b.rule || b.ai);
  const domain = from && to ? [from, to] : [Date.now() - 864e5, Date.now()];

  return (
    <EuiPanel hasBorder>
      <PanelTitle
        title="Alerts over time"
        info={`Wazuh alerts (level 10+) and AI detections, stacked per ${interval ?? "interval"}. A bar that is only AI is a stretch where the AI flagged activity and no Wazuh rule fired.`}
      />
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
              name="Wazuh alerts"
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
            <Axis
              id="y"
              position={Position.Left}
              ticks={4}
              tickFormat={(v) => (Number.isInteger(v) ? String(v) : "")}
            />
          </Chart>
        ) : (
          <EuiEmptyPrompt
            iconType="chartBarVertical"
            titleSize="xs"
            title={<h3>No alerts in this range</h3>}
            body={
              <p>
                No Wazuh alerts at level 10+ and no AI detections in the selected range.
                Widen the time range, or generate some traffic.
              </p>
            }
          />
        )}
      </div>
    </EuiPanel>
  );
}
