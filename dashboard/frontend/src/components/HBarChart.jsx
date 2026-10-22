import {
  Chart,
  Settings,
  BarSeries,
  Axis,
  ScaleType,
  Position,
} from "@elastic/charts";
import { EuiPanel, EuiSpacer, EuiEmptyPrompt } from "@elastic/eui";
import { useTheme, useChartTheme } from "../theme/ThemeProvider";
import PanelTitle from "./PanelTitle";

const LABEL_CHARS = 42; // longer labels (rule descriptions) are cut on the axis; the tooltip has them whole
const ROW_PX = 34;

// A single measure across categories (top IPs, top rules, attack types): one
// hue, magnitude by bar length, the count printed on each bar. `data` is
// [{label, count}]; onBarClick(label) makes the bars a drill-down (the top-IPs
// chart opens the IP pivot). `info` is the panel's explanation, shown on hover.
// The height follows the number of bars, so two categories don't fill a page.
export default function HBarChart({ title, info, data, seriesName, color, empty, onBarClick }) {
  const { baseTheme } = useTheme();
  const theme = useChartTheme();
  const max = Math.max(0, ...(data ?? []).map((d) => d.count));
  const height = data?.length ? Math.min(300, 48 + data.length * ROW_PX) : 180;

  return (
    <EuiPanel hasBorder>
      <PanelTitle title={title} info={info} />
      <EuiSpacer size="s" />
      <div style={{ height }}>
        {data?.length ? (
          <Chart>
            <Settings
              baseTheme={baseTheme}
              theme={theme}
              rotation={90}
              onElementClick={
                onBarClick ? ([[geometry]]) => onBarClick(geometry.datum.label) : undefined
              }
            />
            <BarSeries
              id="bars"
              name={seriesName}
              xScaleType={ScaleType.Ordinal}
              yScaleType={ScaleType.Linear}
              xAccessor="label"
              yAccessors={["count"]}
              color={color}
              data={data}
              displayValueSettings={{ showValueLabel: true }}
            />
            <Axis
              id="label"
              position={Position.Left}
              tickFormat={(v) => (v.length > LABEL_CHARS ? `${v.slice(0, LABEL_CHARS - 1)}…` : v)}
            />
            {/* counts are whole numbers: no 0.5 ticks on a small range */}
            <Axis
              id="count"
              position={Position.Bottom}
              ticks={Math.max(1, Math.min(4, max))}
              tickFormat={(v) => (Number.isInteger(v) ? String(v) : "")}
            />
          </Chart>
        ) : (
          <EuiEmptyPrompt
            iconType={empty.icon}
            titleSize="xs"
            title={<h3>{empty.title}</h3>}
            body={<p>{empty.body}</p>}
          />
        )}
      </div>
    </EuiPanel>
  );
}
