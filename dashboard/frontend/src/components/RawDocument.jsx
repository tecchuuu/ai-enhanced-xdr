import { useEffect, useState } from "react";
import { EuiCodeBlock, EuiCallOut, EuiLoadingSpinner, EuiText } from "@elastic/eui";
import { getAlertDoc } from "../api";

// The stored OpenSearch document behind an alert (full_log, decoder, location,
// every MITRE field...). The flyout mounts this the first time its JSON tab is
// opened, so the fetch only happens when someone wants it; key={alertId}
// starts it fresh for a different alert.
export default function RawDocument({ alertId }) {
  const [doc, setDoc] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getAlertDoc(alertId)
      .then(setDoc)
      .catch((e) => setError(String(e.message ?? e)));
  }, [alertId]);

  if (error) return <EuiCallOut title={error} color="danger" iconType="warning" size="s" />;
  if (!doc) return <EuiLoadingSpinner />;
  return (
    <>
      <EuiText size="xs" color="subdued">
        <p>
          {doc.index} / {doc.id}
        </p>
      </EuiText>
      <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable overflowHeight={520}>
        {JSON.stringify(doc.source, null, 2)}
      </EuiCodeBlock>
    </>
  );
}
