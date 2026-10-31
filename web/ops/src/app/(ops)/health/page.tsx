"use client";

import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, RowsSkeleton } from "@/components/states";
import { Status } from "@/components/status";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import type { Health } from "@/lib/types";

// Placeholder thresholds: tune them against real traffic.
const level = (value: number, ok: number, slow: number, higherIsWorse = true) =>
  (higherIsWorse ? value <= ok : value >= ok) ? "ok" : (higherIsWorse ? value <= slow : value >= slow) ? "slow" : "down";

function tiles(h: Health) {
  return [
    { title: "Proxy p99", value: `${h.proxy_p99_ms} ms`, state: level(h.proxy_p99_ms, 100, 250) },
    { title: "Revocation lag", value: `${h.revocation_lag_s} s`, state: level(h.revocation_lag_s, 5, 30) },
    { title: "Event backlog", value: String(h.event_backlog), state: level(h.event_backlog, 100, 1000) },
    { title: "Uptime, 30 days", value: `${h.uptime_30d_pct}%`, state: level(h.uptime_30d_pct, 99.9, 99, false) },
  ];
}

export default function HealthPage() {
  const health = useResource(api.health);
  const { reload } = health;

  useEffect(() => {
    const timer = setInterval(reload, 15_000);
    return () => clearInterval(timer);
  }, [reload]);

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Platform health</h1>
        <div className="flex items-center gap-3">
          {health.data && <span className="text-xs text-muted-foreground">Updated {new Date(health.data.updated_at).toLocaleTimeString()}</span>}
          <Button variant="outline" onClick={reload} disabled={health.status === "loading"}>Refresh</Button>
        </div>
      </div>
      {health.status === "loading" && !health.data && <RowsSkeleton rows={2} />}
      {health.status === "error" && <ErrorState message={health.error} onRetry={reload} />}
      {health.data && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {tiles(health.data).map((tile) => (
            <Card key={tile.title}>
              <CardHeader>
                <CardDescription>{tile.title}</CardDescription>
                <CardTitle className="font-mono text-3xl tabular-nums">{tile.value}</CardTitle>
                <Status value={tile.state} />
              </CardHeader>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
