import React from "react";
import ReactDOM from "react-dom/client";
import { ThemeProvider } from "./theme/ThemeProvider";
import App from "./App";

// Chart CSS is loaded by ThemeProvider (it swaps per color mode), so nothing
// theme-specific is imported here.
ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </React.StrictMode>
);
