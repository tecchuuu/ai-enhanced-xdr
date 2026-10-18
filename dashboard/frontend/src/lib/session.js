// Who is at the console (recorded on blocks, unblocks and triage) and the API
// key when the server requires one (DASHBOARD_API_KEY). Kept in this browser's
// localStorage — a lab convenience, not a credential store.
const KEY = "aixdr:session";

export function loadSession() {
  try {
    return JSON.parse(localStorage.getItem(KEY)) ?? {};
  } catch {
    return {};
  }
}

export function saveSession(session) {
  try {
    localStorage.setItem(KEY, JSON.stringify(session));
  } catch {
    /* storage disabled: the values last for this page load only */
  }
}
