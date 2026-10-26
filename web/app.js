const api = location.port === '8080' ? '' : 'http://localhost:8080';
const tenantInput = document.querySelector('#tenant');
const tenantHeaders = () => ({ 'X-Tenant-ID': tenantInput.value.trim(), 'Content-Type': 'application/json' });

function notice(message, error = false) {
  const node = document.querySelector('#notice');
  node.textContent = message;
  node.dataset.error = String(error);
  node.classList.add('visible');
  setTimeout(() => node.classList.remove('visible'), 3500);
}

async function request(path, options = {}) {
  const response = await fetch(`${api}${path}`, { ...options, headers: { ...tenantHeaders(), ...options.headers } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error || response.statusText);
  }
  return response.status === 204 ? null : response.json();
}

function escapeHTML(value) {
  const node = document.createElement('div');
  node.textContent = String(value ?? '');
  return node.innerHTML;
}

async function loadAgents() {
  try {
    const agents = await request('/admin/agents');
    document.querySelector('#agent-count').textContent = agents.length;
    document.querySelector('#agents').innerHTML = agents.length
      ? agents.map(agent => `<tr><td><strong>${escapeHTML(agent.id)}</strong></td><td>${escapeHTML(agent.owner_subject)}</td><td><span class="badge">${escapeHTML(agent.status || 'active')}</span></td></tr>`).join('')
      : '<tr><td colspan="3" class="empty">No agents registered</td></tr>';
  } catch (error) { notice(error.message, true); }
}

async function loadApprovals() {
  try {
    const approvals = await request('/approve');
    const pending = approvals.filter(item => item.status === 'pending');
    document.querySelector('#approval-count').textContent = pending.length;
    document.querySelector('#approvals').innerHTML = pending.length
      ? pending.map(item => `<article class="approval"><div><strong>${escapeHTML(item.action)}</strong><p>${escapeHTML(item.task_id)} · ${escapeHTML(item.requester_id)}</p></div><pre>${escapeHTML(JSON.stringify(item.parameters, null, 2))}</pre><div class="approval-actions"><button data-approval="approved" data-id="${escapeHTML(item.id)}" data-parameters="${escapeHTML(JSON.stringify(item.parameters))}">Approve</button><button class="danger" data-approval="denied" data-id="${escapeHTML(item.id)}" data-parameters="${escapeHTML(JSON.stringify(item.parameters))}">Deny</button></div></article>`).join('')
      : '<p class="empty">No pending approvals</p>';
  } catch (error) { notice(error.message, true); }
}

async function loadReplay() {
  try {
    const events = await request('/events/replay');
    document.querySelector('#event-count').textContent = events.length;
    document.querySelector('#replay').innerHTML = events.length
      ? events.map((event, index) => `<article class="timeline-event"><span>${index + 1}</span><div><strong>${escapeHTML(event.payload?.type || 'event')}</strong><pre>${escapeHTML(JSON.stringify(event.payload || {}, null, 2))}</pre></div></article>`).join('')
      : '<p class="empty">No audit events for this tenant</p>';
  } catch (error) { notice(error.message, true); }
}

async function refresh() { await Promise.all([loadAgents(), loadApprovals(), loadReplay()]); }
document.querySelector('#refresh').addEventListener('click', refresh);
document.querySelector('#load-replay').addEventListener('click', loadReplay);

document.querySelector('#revoke').addEventListener('submit', async event => {
  event.preventDefault();
  const scope = document.querySelector('#scope').value;
  const status = document.querySelector('#revoke-status');
  try {
    await request('/revoke', { method: 'POST', body: JSON.stringify({ [scope]: document.querySelector('#scope-id').value }) });
    status.textContent = 'Access revoked'; status.dataset.error = 'false'; event.target.reset();
  } catch (error) { status.textContent = error.message; status.dataset.error = 'true'; }
});

document.querySelector('#approvals').addEventListener('click', async event => {
  const button = event.target.closest('[data-approval]');
  if (!button) return;
  try {
    await request('/approve', { method: 'POST', body: JSON.stringify({ id: button.dataset.id, status: button.dataset.approval, parameters: JSON.parse(button.dataset.parameters) }) });
    notice(`Approval ${button.dataset.approval}`); loadApprovals();
  } catch (error) { notice(error.message, true); }
});

const dialog = document.querySelector('#agent-dialog');
document.querySelector('#register-agent').addEventListener('click', () => { dialog.querySelector('[name="tenant_id"]').value = tenantInput.value.trim(); dialog.showModal(); });
document.querySelector('#agent-form').addEventListener('submit', async event => {
  if (event.submitter?.value === 'cancel') return;
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.currentTarget));
  try { await request('/admin/agents', { method: 'POST', body: JSON.stringify(body) }); dialog.close(); event.currentTarget.reset(); loadAgents(); notice('Agent registered'); }
  catch (error) { notice(error.message, true); }
});

tenantInput.addEventListener('change', () => { localStorage.setItem('lanyard-tenant', tenantInput.value.trim()); refresh(); });
tenantInput.value = localStorage.getItem('lanyard-tenant') || 'tenant-demo';
refresh();
