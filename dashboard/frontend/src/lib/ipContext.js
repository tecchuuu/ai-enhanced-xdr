import { createContext, useContext } from "react";

// Every clickable IP opens the same IP flyout, which App renders once.
export const IpContext = createContext(() => {});
export const useOpenIp = () => useContext(IpContext);
