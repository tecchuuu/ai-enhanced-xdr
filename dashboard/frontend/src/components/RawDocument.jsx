import { useState } from "react";
import { EuiAccordion, EuiCodeBlock, EuiCallOut, EuiLoadingSpinner, EuiText } from "@elastic/eui";
import { getAlertDoc } from "../api";

// The stored OpenSearch document behind an alert (full_log, decoder, location,
// every MITRE field...), fetched the first time the accordion opens. Mount it
// with key={alertId} so a different alert starts closed and empty.
export default function RawDocument({ alertId }) {
  const [doc, setDoc] = useState(null);
  const [error, setError] = useState(null);

  const load = (open) => {
    if (!open || doc || error) return;
    getAlertDoc(alertId)
      .then(setDoc)
      .catch((e) => setError(String(e.message ?? e)));
  };

  return (
    <EuiAccordion
      id={`raw-${alertId}`}
      buttonContent="Raw document"
      onToggle={load}
      paddingSize="s"
    >
      {error ? (
        <EuiCallOut title={error} color="danger" iconType="warning" size="s" />
      ) : doc ? (
        <>
          <EuiText size="xs" color="subdued">
            <p>
              {doc.index} / {doc.id}
            </p>
          </EuiText>
          <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable overflowHeight={420}>
            {JSON.stringify(doc.source, null, 2)}
          </EuiCodeBlock>
        </>
      ) : (
        <EuiLoadingSpinner />
      )}
    </EuiAccordion>
  );
}
