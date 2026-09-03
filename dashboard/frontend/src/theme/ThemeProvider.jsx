import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { EuiProvider } from "@elastic/eui";
import { DARK_THEME, LIGHT_THEME } from "@elastic/charts";
import darkChartCss from "@elastic/charts/dist/theme_only_dark.css?url";
import lightChartCss from "@elastic/charts/dist/theme_only_light.css?url";
import { PALETTES } from "./palette";

const STORAGE_KEY = "aixdr:colorMode";
const ThemeCtx = createContext(null);

function initialMode() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    /* private mode / storage disabled — fall through to the default */
  }
  return "dark";
}

export function ThemeProvider({ children }) {
  const [colorMode, setColorMode] = useState(initialMode);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, colorMode);
    } catch {
      /* non-fatal: the toggle still works for this session */
    }
  }, [colorMode]);

  // @elastic/charts ships one stylesheet per mode and they collide if both are
  // imported, so swap the <link> instead of importing either at build time.
  useEffect(() => {
    const id = "ech-theme";
    let link = document.getElementById(id);
    if (!link) {
      link = document.createElement("link");
      link.id = id;
      link.rel = "stylesheet";
      document.head.appendChild(link);
    }
    link.href = colorMode === "dark" ? darkChartCss : lightChartCss;
  }, [colorMode]);

  const value = useMemo(
    () => ({
      colorMode,
      toggle: () => setColorMode((m) => (m === "dark" ? "light" : "dark")),
      palette: PALETTES[colorMode],
      baseTheme: colorMode === "dark" ? DARK_THEME : LIGHT_THEME,
    }),
    [colorMode]
  );

  return (
    <ThemeCtx.Provider value={value}>
      <EuiProvider colorMode={colorMode}>{children}</EuiProvider>
    </ThemeCtx.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeCtx);
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>");
  return ctx;
}

export const usePalette = () => useTheme().palette;

// Shared chart theme. The bar spacer stroke is the surface color so adjacent
// bars read as separated rather than welded — it must follow the mode.
export function useChartTheme(extra) {
  const { palette } = useTheme();
  return useMemo(
    () => ({
      chartMargins: { top: 8, bottom: 4, left: 4, right: 4 },
      barSeriesStyle: { rect: { strokeWidth: 1, stroke: palette.surface } },
      scales: { barsPadding: 0.25 },
      background: { color: "transparent" },
      ...extra,
    }),
    [palette.surface, extra]
  );
}
