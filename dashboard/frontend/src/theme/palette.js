// Series and status colors.
//
// Two separate jobs, kept on separate hues so they never collide:
//   - severity uses the convention every SOC tool shares: critical red, high
//     orange, medium yellow, low slate. Analysts read it without a legend.
//   - source (Wazuh rule vs AI model) uses blue and purple, which are off that
//     ramp, so a Wazuh row is never mistaken for a "high" one.
//
// Each mode is stepped for its OWN surface — dark is not an automatic flip of
// light. Identity is never carried by color alone: severity and source badges
// are labelled, charts show a legend, and every view has a table.
export const PALETTES = {
  dark: {
    surface: "#0B1628",
    rule: "#4c8df6",
    ai: "#a371f7",
    critical: "#e5484d",
    high: "#f0883e",
    medium: "#e3b341",
    low: "#8b98ad",
  },
  light: {
    surface: "#FFFFFF",
    rule: "#1f6fe5",
    ai: "#8250df",
    critical: "#d92d20",
    high: "#e06c00",
    medium: "#c99a06",
    low: "#6b7a90",
  },
};
