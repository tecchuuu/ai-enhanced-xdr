import { useEffect, useRef, useState } from "react";
import {
  EuiPanel,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiButton,
  EuiFieldText,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHorizontalRule,
} from "@elastic/eui";
import { explainAlert, explainChat } from "../api";

// One bubble in the thread. role: "assistant" (the model) | "user" (analyst).
function Turn({ role, content }) {
  const mine = role === "user";
  return (
    <div style={{ display: "flex", justifyContent: mine ? "flex-end" : "flex-start" }}>
      <EuiPanel
        hasShadow={false}
        hasBorder
        paddingSize="s"
        color={mine ? "primary" : "subdued"}
        style={{ maxWidth: "85%", marginBottom: 6 }}
      >
        <EuiText size="s">
          <p style={{ margin: 0, whiteSpace: "pre-wrap" }}>{content}</p>
        </EuiText>
      </EuiPanel>
    </div>
  );
}

export default function ExplainPanel({ alert, onRefresh }) {
  // thread[0] is the initial explanation (assistant); the rest is Q&A
  const [thread, setThread] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [provider, setProvider] = useState(null);
  const endRef = useRef(null);

  useEffect(() => {
    setThread(alert?.explanation ? [{ role: "assistant", content: alert.explanation }] : []);
    setProvider(alert?.explained_by ?? null);
    setInput("");
    setError(null);
  }, [alert]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "nearest" });
  }, [thread]);

  const started = thread.length > 0;

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await explainAlert(alert.id);
      setThread([{ role: "assistant", content: res.explanation }]);
      setProvider(res.provider);
      onRefresh?.();
    } catch (e) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };

  const send = async () => {
    const q = input.trim();
    if (!q || busy) return;
    const next = [...thread, { role: "user", content: q }];
    setThread(next);
    setInput("");
    setBusy(true);
    setError(null);
    try {
      const res = await explainChat(alert.id, next);
      setThread([...next, { role: "assistant", content: res.reply }]);
      setProvider(res.provider);
    } catch (e) {
      setError(String(e.message ?? e));
      setThread(thread); // roll back the unanswered question
    } finally {
      setBusy(false);
    }
  };

  return (
    <EuiPanel hasBorder color="subdued">
      <EuiTitle size="xxs">
        <h3>Analyst assistant</h3>
      </EuiTitle>
      <EuiSpacer size="s" />

      {!started ? (
        <>
          <EuiText size="s" color="subdued">
            <p>
              Explain this detection in plain English, then ask follow-up questions
              about it.
            </p>
          </EuiText>
          <EuiSpacer size="s" />
          <EuiButton size="s" onClick={start} isLoading={busy}>
            Explain this detection
          </EuiButton>
        </>
      ) : (
        <>
          {thread.map((m, i) => (
            <Turn key={i} role={m.role} content={m.content} />
          ))}
          <div ref={endRef} />
          <EuiHorizontalRule margin="s" />
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem>
              <EuiFieldText
                placeholder="Ask about this alert…"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && send()}
                compressed
                fullWidth
                disabled={busy}
              />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton size="s" onClick={send} isLoading={busy} isDisabled={!input.trim()}>
                Send
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      )}

      {provider && (
        <>
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued">
            provider: {provider}
          </EuiText>
        </>
      )}
      {error && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut title={error} color="danger" iconType="warning" size="s" />
        </>
      )}
    </EuiPanel>
  );
}
