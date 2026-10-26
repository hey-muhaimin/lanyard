const tenant = localStorage.getItem('lanyard-tenant') || 'tenant-demo';
const api = location.port === '8080' ? '' : 'http://localhost:8080';
const headers = { 'X-Tenant-ID': tenant };
async function loadAgents() {
  const response = await fetch(`${api}/admin/agents`, { headers });
  document.querySelector('#agents').textContent = response.ok ? JSON.stringify(await response.json(), null, 2) : response.statusText;
}
async function revoke(event) {
  event.preventDefault();
  const scope = document.querySelector('#scope').value;
  const body = { [scope]: document.querySelector('#scope-id').value, expires_at: new Date(Date.now() + 10 * 60_000).toISOString() };
  const response = await fetch(`${api}/revoke`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!response.ok) alert(await response.text());
}
document.querySelector('#revoke').addEventListener('submit', revoke);
document.querySelector('#refresh').addEventListener('click', loadAgents);
document.querySelector('#replay').textContent = `Tenant ${tenant}: replay available from /events/replay`;
loadAgents();
