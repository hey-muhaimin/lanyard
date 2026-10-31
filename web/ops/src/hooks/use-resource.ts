"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface Resource<T> {
  status: "idle" | "loading" | "ready" | "error";
  data?: T;
  error?: string;
  reload: () => void;
}

/** Loads data on mount (and on reload). Pass enabled=false to skip, e.g. when the role cannot read it. */
export function useResource<T>(load: () => Promise<T>, enabled = true): Resource<T> {
  const [state, setState] = useState<Omit<Resource<T>, "reload">>({ status: enabled ? "loading" : "idle" });
  const [tick, setTick] = useState(0);
  const loader = useRef(load);
  loader.current = load;

  useEffect(() => {
    if (!enabled) {
      setState({ status: "idle" });
      return;
    }
    let live = true;
    setState((current) => ({ ...current, status: "loading", error: undefined }));
    loader.current().then(
      (data) => live && setState({ status: "ready", data }),
      (error: unknown) =>
        live && setState({ status: "error", error: error instanceof Error ? error.message : "Request failed" }),
    );
    return () => {
      live = false;
    };
  }, [enabled, tick]);

  const reload = useCallback(() => setTick((value) => value + 1), []);
  return { ...state, reload };
}
