import { EuiLink, EuiToolTip } from "@elastic/eui";

// T1110.001 -> attack.mitre.org/techniques/T1110/001/, with the tactic on hover.
// Same for both sources: Wazuh tags rule alerts, the AI heuristics tag detections.
export default function MitreLink({ id, tactic }) {
  if (!id) return "—";
  const link = (
    <EuiLink
      href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`}
      target="_blank"
      external
      onClick={(e) => e.stopPropagation()}
    >
      {id}
    </EuiLink>
  );
  return tactic ? <EuiToolTip content={tactic}>{link}</EuiToolTip> : link;
}
