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

// single measure across categories: one hue, magnitude carried by bar length
const BAR = "#0ca58c";

const theme = {
  chartMargins: { top: 8, bottom: 4, left: 4, right: 4 },
  barSeriesStyle: { rect: { strokeWidth: 1, stroke: "#1a1a19" } },
  scales: { barsPadding: 0.25 },
};

const pretty = (c) => (c ? c.replace(/_/g, " ") : "—");

export default function CategoryBreakdown({ categories, hours }) {
  const data = (categories ?? []).map((c) => ({ ...c, label: pretty(c.category) }));

  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>AI detections by category</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>
          Heuristic post-classification of anomalous windows{hours ? `, last ${hours}` : ""}.
          The model flags the deviation; the category makes it triageable.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {data.length ? (
        <div style={{ height: 260 }}>
          <Chart>
            <Settings baseTheme={DARK_THEME} theme={theme} rotation={90} />
            <BarSeries
              id="cat"
              name="Detections"
              xScaleType={ScaleType.Ordinal}
              yScaleType={ScaleType.Linear}
              xAccessor="label"
              yAccessors={["count"]}
              color={BAR}
              data={data}
            />
            <Axis id="cat" position={Position.Left} />
            <Axis id="count" position={Position.Bottom} ticks={4} integersOnly />
          </Chart>
        </div>
      ) : (
        <EuiEmptyPrompt
          iconType="visBarHorizontal"
          titleSize="xs"
          title={<h3>No categorised detections yet</h3>}
          body={<p>AI detections with an <code>ai.category</code> will break down here.</p>}
        />
      )}
    </EuiPanel>
  );
}
