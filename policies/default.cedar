permit (
  principal is Agent,
  action,
  resource is Resource
) when {
  principal.status == "active" &&
  principal.tenantId == context.tenantId &&
  context.connector == resource.connector &&
  context.rowLimit <= 1000 &&
  context.ttlSeconds <= 600
};

forbid (
  principal,
  action,
  resource
) unless {
  context.approval.status == "granted"
};
