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

// A single measure across categories (top IPs, detection categories): one hue,
// magnitude by bar length. `data` is [{label, count}]; onBarClick(label) makes
// the bars a drill-down (the top-IPs chart opens the IP pivot). `info` is the
// panel's explanation, shown on hover.
export default function HBarChart({ title, info, data, seriesName, color, empty, onBarClick }) {
  const { baseTheme } = useTheme();
  const theme = useChartTheme();

  return (
    <EuiPanel hasBorder>
      <PanelTitle title={title} info={info} />
      <EuiSpacer size="s" />
      <div style={{ height: 260 }}>
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
            />
            <Axis id="label" position={Position.Left} />
            <Axis id="count" position={Position.Bottom} ticks={4} integersOnly />
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
