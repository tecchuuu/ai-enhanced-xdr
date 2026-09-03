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

const pretty = (c) => (c ? c.replace(/_/g, " ") : "—");

export default function CategoryBreakdown({ categories, hours }) {
  const { baseTheme } = useTheme();
  const p = usePalette();
  const theme = useChartTheme();
  const data = (categories ?? []).map((c) => ({
    ...c,
    label: pretty(c.category),
  }));

  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>AI detections by category</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>
          Heuristic post-classification of anomalous windows
          {hours ? `, last ${hours}` : ""}. The model flags the deviation; the
          category makes it triageable.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <div style={{ height: 260 }}>
        {data.length ? (
          <Chart>
            {/* single measure across categories: one hue, magnitude by bar length */}
            <Settings baseTheme={baseTheme} theme={theme} rotation={90} />
            <BarSeries
              id="cat"
              name="Detections"
              xScaleType={ScaleType.Ordinal}
              yScaleType={ScaleType.Linear}
              xAccessor="label"
              yAccessors={["count"]}
              color={p.ai}
              data={data}
            />
            <Axis id="cat" position={Position.Left} />
            <Axis
              id="count"
              position={Position.Bottom}
              ticks={4}
              integersOnly
            />
          </Chart>
        ) : (
          <EuiEmptyPrompt
            iconType="visBarVertical"
            titleSize="xs"
            title={<h3>No categorised detections yet</h3>}
            body={
              <p>
                Nothing in this range. Generate traffic and give the consumer
                ~10 minutes to fill its window buffer, or widen the time range.
              </p>
            }
          />
        )}
      </div>
    </EuiPanel>
  );
}
