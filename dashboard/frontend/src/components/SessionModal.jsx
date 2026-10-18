import { useState } from "react";
import {
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiButton,
  EuiButtonEmpty,
  EuiForm,
  EuiFormRow,
  EuiFieldText,
  EuiFieldPassword,
  EuiCallOut,
  EuiSpacer,
} from "@elastic/eui";
import { loadSession, saveSession } from "../lib/session";

// Who is at the console, and the API key when the server asks for one.
// onClose(true) after saving, onClose(false) on cancel.
export default function SessionModal({ keyRequired, rejected, onClose }) {
  const current = loadSession();
  const [analyst, setAnalyst] = useState(current.analyst ?? "");
  const [apiKey, setApiKey] = useState(current.apiKey ?? "");

  const save = () => {
    saveSession({ analyst: analyst.trim(), apiKey: apiKey.trim() });
    onClose(true);
  };

  return (
    <EuiModal onClose={() => onClose(false)} initialFocus="[name=analyst]">
      <EuiModalHeader>
        <EuiModalHeaderTitle>Who&rsquo;s at the console?</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        {rejected && (
          <>
            <EuiCallOut
              size="s"
              color="danger"
              iconType="lock"
              title="The API refused the request — enter the key from DASHBOARD_API_KEY."
            />
            <EuiSpacer size="m" />
          </>
        )}
        <EuiForm
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
        >
          <EuiFormRow label="Analyst name" helpText="Recorded on blocks, unblocks and triage changes.">
            <EuiFieldText name="analyst" value={analyst} onChange={(e) => setAnalyst(e.target.value)} />
          </EuiFormRow>
          {keyRequired && (
            <EuiFormRow label="API key" helpText="DASHBOARD_API_KEY in dashboard/.env on the server.">
              <EuiFieldPassword
                type="dual"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </EuiFormRow>
          )}
          <button type="submit" hidden />
        </EuiForm>
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={() => onClose(false)}>Cancel</EuiButtonEmpty>
        <EuiButton fill onClick={save} isDisabled={keyRequired && !apiKey.trim()}>
          Save
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
}
