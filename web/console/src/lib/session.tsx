"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, UNAUTHENTICATED_EVENT } from "./api";
import type { Principal } from "./types";

type State = { status: "loading" } | { status: "anon" } | { status: "authed"; user: Principal };

interface SessionContext {
  state: State;
  signIn: (user: Principal) => void;
  signOut: () => Promise<void>;
}

const Context = createContext<SessionContext | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let live = true;
    api
      .me()
      .then((user) => live && setState({ status: "authed", user }))
      .catch(() => live && setState({ status: "anon" }));
    const onExpired = () => setState({ status: "anon" });
    window.addEventListener(UNAUTHENTICATED_EVENT, onExpired);
    return () => {
      live = false;
      window.removeEventListener(UNAUTHENTICATED_EVENT, onExpired);
    };
  }, []);

  const signIn = useCallback((user: Principal) => setState({ status: "authed", user }), []);
  const signOut = useCallback(async () => {
    await api.logout().catch(() => undefined);
    setState({ status: "anon" });
  }, []);

  const value = useMemo(() => ({ state, signIn, signOut }), [state, signIn, signOut]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useSession(): SessionContext {
  const value = useContext(Context);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}

export function useUser(): Principal | undefined {
  const { state } = useSession();
  return state.status === "authed" ? state.user : undefined;
}
