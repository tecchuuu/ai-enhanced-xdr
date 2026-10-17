import { useState } from "react";
import { EuiFieldSearch } from "@elastic/eui";

// Server-side search for a feed: runs on Enter (or when cleared), so typing
// doesn't fire a query per keystroke. The API matches IPs, users, rule ids and
// words across the alert's fields — including ones the table doesn't show.
export default function FeedSearch({ onSearch, placeholder }) {
  const [draft, setDraft] = useState("");
  return (
    <EuiFieldSearch
      fullWidth
      compressed
      isClearable
      placeholder={placeholder}
      value={draft}
      onChange={(e) => {
        setDraft(e.target.value);
        if (!e.target.value) onSearch("");
      }}
      onSearch={(v) => onSearch(v.trim())}
    />
  );
}
