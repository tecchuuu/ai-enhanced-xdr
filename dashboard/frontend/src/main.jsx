import React from "react";
import ReactDOM from "react-dom/client";
import { EuiProvider } from "@elastic/eui";
import "@elastic/charts/dist/theme_only_dark.css";
import App from "./App";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <EuiProvider colorMode="dark">
      <App />
    </EuiProvider>
  </React.StrictMode>
);
