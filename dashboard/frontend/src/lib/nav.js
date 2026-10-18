import { createContext, useContext } from "react";

// What any component can open: the IP pivot, the alert flyout, another page
// (goto takes a route patch, e.g. {page: "events", agent: "web-01"}). App
// provides it; each one is a change to the URL (lib/route.js).
export const NavContext = createContext({ openIp() {}, openAlert() {}, goto() {} });
export const useNav = () => useContext(NavContext);
