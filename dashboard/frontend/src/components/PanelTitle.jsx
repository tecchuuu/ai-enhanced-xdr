import { EuiTitle, EuiIconTip } from "@elastic/eui";

// A panel heading whose explanation sits in an ⓘ tooltip rather than a
// paragraph under it: the console stays dense, the reasoning stays one hover away.
export default function PanelTitle({ title, info, size = "xs", as: Tag = "h2" }) {
  return (
    <EuiTitle size={size}>
      <Tag>
        {title}
        {info && (
          <>
            {" "}
            <EuiIconTip content={info} type="info" color="subdued" aria-label={`About: ${title}`} />
          </>
        )}
      </Tag>
    </EuiTitle>
  );
}
