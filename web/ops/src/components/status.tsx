// No color anywhere: every status is a glyph plus a word.
const statuses: Record<string, readonly [string, string]> = {
  active: ["●", "Active"],
  allowed: ["●", "Allowed"],
  approved: ["●", "Approved"],
  pending: ["○", "Pending"],
  expired: ["○", "Expired"],
  needs_approval: ["◆", "Needs approval"],
  denied: ["■", "Denied"],
  suspended: ["■", "Suspended"],
  deleted: ["■", "Deleted"],
  executed: ["●", "Executed"],
  over_quota: ["○", "Over quota"],
  ok: ["●", "Healthy"],
  slow: ["○", "Degraded"],
  down: ["■", "Failing"],
};

export function Status({ value }: { value: string }) {
  const [glyph, label] = statuses[value] ?? ["○", value];
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span aria-hidden className="font-mono">{glyph}</span>
      {label}
    </span>
  );
}
