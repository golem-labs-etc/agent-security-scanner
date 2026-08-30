/**
 * Glance surfaces pane.
 *
 * Polls GET /stats, which is a cache read. It does NOT poll POST /scan on a
 * timer: that would be a full disk rescan every interval, per open window.
 * Scanning is behind the button, and the button is the only thing that starts
 * one.
 *
 * Colours come from theme variables only. No hardcoded values and no pane
 * background, so the pane inherits whatever the host is wearing.
 *
 * The category colour map is built from the list the API returns, which the
 * API takes from the scanner's own exported CATEGORIES. It is exhaustive by
 * construction rather than by maintenance: a category added in the scanner
 * arrives here with a slot already assigned, and there is no second list to
 * forget to update.
 */

const API = '/api/plugins/glance-surfaces';
const POLL_MS = 30000;

/**
 * Palette assigned by index over whatever categories the API reports.
 * Every entry is a theme variable with a documented fallback chain, so an
 * unstyled host still renders readable text rather than nothing.
 */
const CATEGORY_SWATCHES = [
  'var(--accent-1, var(--color-accent, currentColor))',
  'var(--accent-2, var(--color-info, currentColor))',
  'var(--accent-3, var(--color-success, currentColor))',
  'var(--accent-4, var(--color-warning, currentColor))',
  'var(--accent-5, var(--color-danger, currentColor))',
  'var(--accent-6, var(--color-muted, currentColor))',
];

const SEVERITY_COLOR = {
  critical: 'var(--color-danger, var(--color-error, currentColor))',
  high: 'var(--color-warning, var(--color-danger, currentColor))',
  medium: 'var(--color-info, var(--color-muted, currentColor))',
  info: 'var(--color-muted, currentColor)',
};

function categoryColor(categories, name) {
  const i = categories.indexOf(name);
  if (i < 0) return 'var(--color-muted, currentColor)';
  return CATEGORY_SWATCHES[i % CATEGORY_SWATCHES.length];
}

function el(tag, props = {}, children = []) {
  const n = document.createElement(tag);
  Object.entries(props).forEach(([k, v]) => {
    if (k === 'style') Object.assign(n.style, v);
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v);
  });
  (Array.isArray(children) ? children : [children]).forEach((c) => {
    if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return n;
}

function renderCounts(counts, categories) {
  const row = el('div', {
    style: { display: 'flex', gap: '1rem', flexWrap: 'wrap', margin: '0.5rem 0' },
  });
  ['critical', 'high', 'medium', 'info'].forEach((sev) => {
    row.appendChild(
      el('span', { style: { color: SEVERITY_COLOR[sev] } }, `${sev} ${counts[sev] ?? 0}`)
    );
  });
  return row;
}

function renderLegend(categories) {
  if (!categories.length) {
    return el(
      'p',
      { style: { color: 'var(--color-muted, currentColor)' } },
      'Category list unavailable: glance-scanner was not found on PATH.'
    );
  }
  const wrap = el('div', {
    style: { display: 'flex', gap: '0.75rem', flexWrap: 'wrap', fontSize: '0.85em' },
  });
  categories.forEach((c) => {
    wrap.appendChild(
      el('span', { style: { color: categoryColor(categories, c) } }, c)
    );
  });
  return wrap;
}

function render(root, stats) {
  const categories = stats.categories || [];
  root.textContent = '';

  root.appendChild(el('h3', { text: 'Agent surfaces' }));

  if (!stats.scanner_available) {
    root.appendChild(
      el(
        'p',
        { style: { color: SEVERITY_COLOR.high } },
        'glance-scanner is not on PATH. Nothing is being scanned.'
      )
    );
  }

  root.appendChild(
    el(
      'p',
      { style: { color: 'var(--color-muted, currentColor)' } },
      stats.scanned_at
        ? `Scanned ${stats.total_scanned} surfaces at ${stats.scanned_at} under policy ${stats.policy || 'strict'}.`
        : 'No scan yet.'
    )
  );

  root.appendChild(renderCounts(stats.counts || {}, categories));

  if (stats.baselined) {
    root.appendChild(
      el(
        'p',
        { style: { color: 'var(--color-muted, currentColor)' } },
        `${stats.baselined} finding(s) baselined at first run and not reported.`
      )
    );
  }

  (stats.warnings || []).forEach((w) => {
    root.appendChild(el('p', { style: { color: SEVERITY_COLOR.medium } }, w.message || ''));
  });

  if (stats.last_error) {
    root.appendChild(
      el('p', { style: { color: SEVERITY_COLOR.high } }, `Last error: ${stats.last_error}`)
    );
  }

  root.appendChild(renderLegend(categories));

  const btn = el('button', {
    type: 'button',
    style: { marginTop: '0.75rem' },
    text: stats.scanning ? 'Scanning...' : 'Scan now',
  });
  if (stats.scanning) btn.setAttribute('disabled', 'disabled');
  btn.addEventListener('click', async () => {
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Scanning...';
    try {
      await fetch(`${API}/scan`, { method: 'POST' });
    } catch (e) {
      /* the next poll reports the real state */
    }
    poll(root);
  });
  root.appendChild(btn);
}

async function poll(root) {
  try {
    const res = await fetch(`${API}/stats`);
    render(root, await res.json());
  } catch (e) {
    root.textContent = '';
    root.appendChild(
      el(
        'p',
        { style: { color: 'var(--color-muted, currentColor)' } },
        'Glance surfaces: stats unavailable.'
      )
    );
  }
}

export function mount(root) {
  poll(root);
  const timer = setInterval(() => poll(root), POLL_MS);
  return () => clearInterval(timer);
}

export default { mount };
