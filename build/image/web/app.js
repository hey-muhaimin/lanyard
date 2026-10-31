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

async function loadAgents() {
  try {
    const agents = await request('/admin/agents');
    document.querySelector('#agent-count').textContent = agents.length;
    const tbody = document.querySelector('#agents');
    tbody.textContent = '';
    if (agents.length) {
      for (const agent of agents) {
        const tr = document.createElement('tr');
        const tdId = document.createElement('td');
        const strong = document.createElement('strong');
        strong.textContent = agent.id ?? '';
        tdId.appendChild(strong);
        const tdOwner = document.createElement('td');
        tdOwner.textContent = agent.owner_subject ?? '';
        const tdStatus = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = agent.status || 'active';
        tdStatus.appendChild(badge);
        tr.appendChild(tdId);
        tr.appendChild(tdOwner);
        tr.appendChild(tdStatus);
        tbody.appendChild(tr);
      }
    } else {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 3;
      td.className = 'empty';
      td.textContent = 'No agents registered';
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  } catch (error) { notice(error.message, true); }
}

async function loadApprovals() {
  try {
    const approvals = await request('/approve');
    const pending = approvals.filter(item => item.status === 'pending');
    document.querySelector('#approval-count').textContent = pending.length;
    const container = document.querySelector('#approvals');
    container.textContent = '';
    if (pending.length) {
      for (const item of pending) {
        const article = document.createElement('article');
        article.className = 'approval';
        const div = document.createElement('div');
        const strong = document.createElement('strong');
        strong.textContent = item.action ?? '';
        const p = document.createElement('p');
        p.textContent = `${item.task_id ?? ''} · ${item.requester_id ?? ''}`;
        div.appendChild(strong);
        div.appendChild(p);
        const pre = document.createElement('pre');
        pre.textContent = JSON.stringify(item.parameters, null, 2);
        const actions = document.createElement('div');
        actions.className = 'approval-actions';
        const approveBtn = document.createElement('button');
        approveBtn.dataset.approval = 'approved';
        approveBtn.dataset.id = item.id ?? '';
        approveBtn.dataset.parameters = JSON.stringify(item.parameters);
        approveBtn.textContent = 'Approve';
        const denyBtn = document.createElement('button');
        denyBtn.className = 'danger';
        denyBtn.dataset.approval = 'denied';
        denyBtn.dataset.id = item.id ?? '';
        denyBtn.dataset.parameters = JSON.stringify(item.parameters);
        denyBtn.textContent = 'Deny';
        actions.appendChild(approveBtn);
        actions.appendChild(denyBtn);
        article.appendChild(div);
        article.appendChild(pre);
        article.appendChild(actions);
        container.appendChild(article);
      }
    } else {
      const p = document.createElement('p');
      p.className = 'empty';
      p.textContent = 'No pending approvals';
      container.appendChild(p);
    }
  } catch (error) { notice(error.message, true); }
}

async function loadReplay() {
  try {
    const events = await request('/events/replay');
    document.querySelector('#event-count').textContent = events.length;
    const container = document.querySelector('#replay');
    container.textContent = '';
    if (events.length) {
      for (let index = 0; index < events.length; index++) {
        const event = events[index];
        const article = document.createElement('article');
        article.className = 'timeline-event';
        const span = document.createElement('span');
        span.textContent = String(index + 1);
        const div = document.createElement('div');
        const strong = document.createElement('strong');
        strong.textContent = event.payload?.type || 'event';
        const pre = document.createElement('pre');
        pre.textContent = JSON.stringify(event.payload || {}, null, 2);
        div.appendChild(strong);
        div.appendChild(pre);
        article.appendChild(span);
        article.appendChild(div);
        container.appendChild(article);
      }
    } else {
      const p = document.createElement('p');
      p.className = 'empty';
      p.textContent = 'No audit events for this tenant';
      container.appendChild(p);
    }
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
    await request('/approve', { method: 'POST', body: JSON.stringify({ id: button.dataset.id, status: button.dataset.approval, parameters: JSON.parse(button.dataset.parameters || '{}') }) });
    notice(`Approval ${button.dataset.approval}`); loadApprovals();
  } catch (error) { notice(error.message, true); }
});
