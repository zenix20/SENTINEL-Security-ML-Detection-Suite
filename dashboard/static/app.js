let currentFilter = 'all';
let knownIds = new Set();
const MAX_ROWS = 60;

const feedScroll = document.getElementById('feed-scroll');
const feedEmpty = document.getElementById('feed-empty');
const template = document.getElementById('feed-row-template');

function timeAgo(ts) {
  const diff = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (diff < 2) return 'now';
  if (diff < 60) return `${diff}s ago`;
  return `${Math.floor(diff / 60)}m ago`;
}

function barClass(entry) {
  if (entry.match === false) return 'mismatch';
  return entry.status === 'alert' ? 'alert' : 'clear';
}

function ringColor(entry) {
  if (entry.match === false) return '#FFB454';
  return entry.status === 'alert' ? '#FF5C5C' : '#3DDC97';
}

function buildRow(entry) {
  const node = template.content.cloneNode(true);
  const row = node.querySelector('.feed-row');

  row.querySelector('.fr-bar').classList.add(barClass(entry));

  const moduleEl = row.querySelector('.fr-module');
  moduleEl.textContent = entry.module.toUpperCase();
  moduleEl.classList.add(entry.module);

  row.querySelector('.fr-label').textContent = entry.label;
  row.querySelector('.fr-time').textContent = timeAgo(entry.timestamp);
  row.querySelector('.fr-detail').textContent = entry.detail || '';

  const ringFg = row.querySelector('.fr-ring-fg');
  const circumference = 97.4;
  const offset = circumference - (entry.confidence / 100) * circumference;
  ringFg.style.stroke = ringColor(entry);
  ringFg.style.strokeDashoffset = circumference;
  requestAnimationFrame(() => { ringFg.style.strokeDashoffset = offset; });

  row.querySelector('.fr-confidence-value').textContent = Math.round(entry.confidence) + '%';
  row.dataset.id = entry.id;
  row.dataset.module = entry.module;
  return row;
}

async function fetchFeed() {
  try {
    const res = await fetch(`/api/feed?module=${currentFilter}`);
    const data = await res.json();
    if (data.length === 0) { feedEmpty.style.display = 'block'; return; }
    feedEmpty.style.display = 'none';

    const newOnes = data.filter(e => !knownIds.has(e.id)).reverse();
    newOnes.forEach(entry => {
      knownIds.add(entry.id);
      feedScroll.insertBefore(buildRow(entry), feedScroll.firstChild);
    });

    while (feedScroll.children.length > MAX_ROWS) {
      feedScroll.removeChild(feedScroll.lastChild);
    }

    [...feedScroll.children].forEach(row => {
      const match = data.find(e => String(e.id) === row.dataset.id);
      if (match) {
        const timeEl = row.querySelector('.fr-time');
        if (timeEl) timeEl.textContent = timeAgo(match.timestamp);
      }
    });
  } catch(err) { console.error('Feed fetch failed', err); }
}

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    document.getElementById('stat-total').textContent = data.total;
    document.getElementById('stat-alerts').textContent = data.alerts;
    document.getElementById('stat-accuracy').textContent =
      data.live_accuracy !== null ? `${data.live_accuracy}%` : '—';
  } catch(err) { console.error('Stats fetch failed', err); }
}

function setFilter(filter) {
  currentFilter = filter;
  knownIds = new Set();
  feedScroll.innerHTML = '';
  feedEmpty.style.display = 'block';
  feedEmpty.textContent = 'Loading…';
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filter);
  });
  fetchFeed();
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => setFilter(btn.dataset.filter));
});

const scanInput = document.getElementById('scan-url-input');
const scanBtn = document.getElementById('scan-url-btn');

async function submitScan() {
  const url = scanInput.value.trim();
  if (!url) return;
  scanBtn.textContent = '...';
  scanBtn.disabled = true;
  try {
    const res = await fetch('/api/scan_url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (!data.error) {
      scanInput.value = '';
      if (currentFilter === 'intrusion') setFilter('phishing');
      else fetchFeed();
    }
  } catch(err) { console.error('Scan failed', err); }
  finally { scanBtn.textContent = 'SCAN'; scanBtn.disabled = false; }
}

scanBtn.addEventListener('click', submitScan);
scanInput.addEventListener('keydown', e => { if (e.key === 'Enter') submitScan(); });

fetchFeed();
fetchStats();
setInterval(fetchFeed, 1500);
setInterval(fetchStats, 4000);
