import type { ReactNode } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-2 border border-dashed p-6">
      <p className="font-medium">{title}</p>
      {children && <p className="max-w-prose text-sm text-muted-foreground">{children}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <Alert variant="destructive">
      <AlertTitle>■ Could not load this</AlertTitle>
      <AlertDescription>
        <p>{message ?? "The request failed."}</p>
        {onRetry && <Button variant="outline" size="sm" className="mt-2" onClick={onRetry}>Try again</Button>}
      </AlertDescription>
    </Alert>
  );
}

export function NoAccess({ what }: { what: string }) {
  return <EmptyState title="Your role cannot view this">Ask a workspace admin if you need access to {what}.</EmptyState>;
}

export function RowsSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="grid gap-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className="h-10 w-full" />)}
    </div>
  );
}

export function ComingSoon({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="grid max-w-prose gap-2">
      <h2 className="text-lg font-semibold">{title}</h2>
      <EmptyState title="Not available yet">{children}</EmptyState>
    </div>
  );
}
