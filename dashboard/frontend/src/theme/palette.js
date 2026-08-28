// Series and status colors.
//
// Each mode is stepped for its OWN surface — dark is not an automatic flip of
// light. Both sets were run through the dataviz six-checks (lightness band,
// chroma floor, CVD separation, normal-vision floor, contrast vs surface)
// against the EUI Borealis surfaces below, and pass.
//
//   dark  surface #0B1628 (navy) — rule/ai worst adjacent CVD dE 12.3, all >= 3:1
//   light surface #FFFFFF        — rule/ai worst adjacent CVD dE  9.2
//
// The light `ai` step sits at 2.82:1 contrast, just under the 3:1 floor. That
// is legal here because identity is never carried by color alone in this UI:
// source badges are labelled "rule"/"AI model", charts show a legend, and every
// view has a table. Darkening it to clear 3:1 costs more CVD separation than it
// buys (measured: dE 9.2 -> 6.2), so it stays.
export const PALETTES = {
  dark: {
    surface: "#0B1628",
    rule: "#d95926",
    ai: "#0ca58c",
    high: "#e66767",
    single: "#3987e5", // single-measure bars: one hue, magnitude by length
  },
  light: {
    surface: "#FFFFFF",
    rule: "#eb6834",
    ai: "#1baf7a",
    high: "#e34948",
    single: "#2a78d6",
  },
};
