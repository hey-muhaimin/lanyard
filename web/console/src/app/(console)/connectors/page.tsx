"use client";

import { ComingSoon } from "@/components/states";

export default function Page() {
  return (
    <ComingSoon title="Connectors">
      Connector secrets cannot be stored yet. The control plane is not connected to the encrypted secret store, so it refuses secrets rather than keeping them in memory.
    </ComingSoon>
  );
}
