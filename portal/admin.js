/* Live data replaces only result fragments, never an in-progress form. */
function openUserActions(row) {
  const dialog = document.getElementById('user-actions-dialog');
  const template = document.getElementById('actions-' + row.dataset.user);
  if (!dialog || !template) return;
  document.getElementById('user-actions-title').textContent = row.dataset.title;
  document.getElementById('user-actions-content').replaceChildren(template.content.cloneNode(true));
  dialog.showModal();
}
document.addEventListener('click', e => {
  const row = e.target.closest('tr[data-user]');
  if (row && !e.target.closest('a,button,input,select,form,summary')) openUserActions(row);
  if (e.target instanceof HTMLDialogElement) {
    const r = e.target.getBoundingClientRect();
    if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) e.target.close();
  }
});
document.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('tr[data-user]')) {
    e.preventDefault(); openUserActions(e.target);
  }
});
function filterUsers() {
  const input = document.querySelector('input[type=search]');
  const value = input ? input.value.toLowerCase() : '';
  document.querySelectorAll('#user-rows tr[data-name]').forEach(row => { row.hidden = !row.dataset.name.includes(value); });
}
document.addEventListener('DOMContentLoaded', () => {
  const users = document.getElementById('user-rows');
  const servers = document.getElementById('server-rows');
  if (!users && !servers) return;
  let timer, busy = false;
  async function refresh() {
    clearTimeout(timer);
    if (document.hidden || busy) { timer = setTimeout(refresh, 8000); return; }
    busy = true;
    const status = document.getElementById('live-state');
    try {
      const url = new URL(users ? '/admin/live' : '/admin/servers/live', location.origin);
      for (const key of ['g','job']) if (new URL(location.href).searchParams.has(key)) url.searchParams.set(key, new URL(location.href).searchParams.get(key));
      const response = await fetch(url, {headers:{'Accept':'application/json'}, signal:AbortSignal.timeout(25000)});
      if (!response.ok || response.redirected) throw new Error('connection');
      const data = await response.json();
      if (users) {
        if (!users.contains(document.activeElement)) users.innerHTML = data.rows;
        document.getElementById('user-count').textContent = data.count;
        document.getElementById('user-online').textContent = data.online;
        const groups = document.getElementById('user-groups');
        if (groups && !groups.contains(document.activeElement)) groups.innerHTML = data.groups;
        document.getElementById('system-summary').innerHTML = data.summary;
        document.getElementById('live-updated').textContent = '· ' + data.updated;
        try { const sort = localStorage.getItem('gvSort'); if (sort && typeof sortUsers === 'function') sortUsers(...sort.split(':')); } catch (_) {}
        filterUsers();
      } else {
        for (const [id,key] of [['server-rows','rows'],['server-chain','chain'],['server-job','job'],['server-events','events'],['server-errors','errors']]) {
          const element = document.getElementById(id);
          if (element && !element.contains(document.activeElement) && !element.querySelector('details[open]')) element.innerHTML = data[key];
        }
        if (typeof bindAddressForms === 'function') bindAddressForms();
        const overview = document.getElementById('server-overview');
        if (overview && data.overview) overview.textContent = data.overview;
      }
      if (status) status.textContent = 'обновляется автоматически';
    } catch (_) {
      if (status) status.textContent = 'нет связи · повторяем подключение';
    } finally { busy = false; timer = setTimeout(refresh, 8000); }
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  timer = setTimeout(refresh, 8000);
});
