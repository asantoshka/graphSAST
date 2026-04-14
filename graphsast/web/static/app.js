/* GraphSAST Web UI — Cytoscape.js graph + findings dashboard */

// ── State ──────────────────────────────────────────────────────────────────
let cy = null;
let allFindings = [];
let findingsWithNodes = new Set();
let _targetPath = '';
let _allNodes = [];

// ── Utilities ──────────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

async function apiFetch(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error ${res.status}: ${url}`);
  return res.json();
}

function sevClass(sev) { return `sev sev-${sev || 'UNKNOWN'}`; }
function verdClass(verd) { return `verd verd-${verd || 'null'}`; }
function verdLabel(verd) {
  if (!verd) return '–';
  return { CONFIRMED: 'Confirmed', FALSE_POSITIVE: 'False Pos.', NEEDS_REVIEW: 'Needs Review' }[verd] || verd;
}
function shortPath(p, len = 40) {
  if (!p || p.length <= len) return p || '—';
  return '…' + p.slice(-(len - 1));
}
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}


// ── View switching ─────────────────────────────────────────────────────────
$$('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.nav-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const view = btn.dataset.view;
    $$('.view').forEach(v => v.classList.remove('active'));
    $(`#view-${view}`).classList.add('active');

    if (view === 'graph') {
      // Force Cytoscape to re-measure the container after it becomes visible
      if (cy) { cy.resize(); cy.fit(); }
    }
    if (view === 'findings') {
      // Always re-render — allFindings may have been populated by loadGraphFull
      if (allFindings.length > 0) {
        renderFindings(allFindings);
      } else {
        loadFindings();
      }
    }
    if (view === 'runs') loadRuns();
  });
});

// ── Stats bar ──────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const data = await apiFetch('/api/stats');
    _targetPath = (data.target || '').replace(/\/?$/, '/');
    $('#target-label').textContent = data.target || '';
    $('#stat-nodes').textContent = `${(data.graph.total_nodes || 0).toLocaleString()} nodes`;
    $('#stat-edges').textContent = `${(data.graph.total_edges || 0).toLocaleString()} edges`;
    const bySev = data.findings?.by_severity || {};
    $('#stat-critical').textContent = `${bySev.CRITICAL || 0} CRITICAL`;
    $('#stat-high').textContent    = `${bySev.HIGH || 0} HIGH`;
    $('#stat-medium').textContent  = `${bySev.MEDIUM || 0} MEDIUM`;
    $('#stat-low').textContent     = `${bySev.LOW || 0} LOW`;
  } catch (e) {
    console.error('loadStats', e);
  }
}

// ── Graph view ─────────────────────────────────────────────────────────────
const KIND_COLORS = {
  File: '#64748b', Class: '#22c55e', Function: '#f97316', Type: '#a78bfa', Test: '#3b82f6',
};
function nodeColor(kind) { return KIND_COLORS[kind] || '#94a3b8'; }

function buildCyNodes(nodes) {
  const showTests = $('#toggle-tests').checked;
  const showFiles = $('#toggle-files').checked;
  return nodes
    .filter(n => {
      if (!showTests && n.is_test) return false;
      if (!showFiles && n.kind === 'File') return false;
      return true;
    })
    .map(n => ({
      data: {
        id: n.qualified_name,
        label: n.name,
        kind: n.kind,
        color: nodeColor(n.kind),
        hasFinding: findingsWithNodes.has(n.file_path),
        file_path: n.file_path,
        line_start: n.line_start,
        line_end: n.line_end,
        qualified_name: n.qualified_name,
        language: n.language,
        params: n.params,
        return_type: n.return_type,
        is_test: n.is_test,
      },
    }));
}

function buildCyEdges(edges) {
  return edges.map(e => ({
    data: { id: `e-${e.id}`, source: e.source, target: e.target, kind: e.kind },
  }));
}

const CY_STYLE = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      'label': 'data(label)',
      'font-size': '9px',
      'color': '#e2e8f0',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': '4px',
      'width': '22px',
      'height': '22px',
      'text-max-width': '80px',
      'text-wrap': 'ellipsis',
      'border-width': 0,
      'min-zoomed-font-size': 7,
    },
  },
  { selector: 'node[kind = "File"]', style: { shape: 'rectangle', width: '18px', height: '18px' } },
  { selector: 'node[kind = "Class"]', style: { shape: 'diamond', width: '26px', height: '26px' } },
  {
    selector: 'node[?hasFinding]',
    style: { 'border-width': 3, 'border-color': '#ef4444', 'width': '26px', 'height': '26px' },
  },
  { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#6366f1' } },
  {
    selector: 'edge',
    style: {
      'width': 1,
      'line-color': '#2e3250',
      'target-arrow-color': '#2e3250',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'opacity': 0.7,
      'arrow-scale': 0.8,
    },
  },
  { selector: 'edge[kind = "CALLS"]',       style: { 'line-color': '#4b5563', 'target-arrow-color': '#4b5563' } },
  { selector: 'edge[kind = "INHERITS"]',    style: { 'line-color': '#22c55e', 'target-arrow-color': '#22c55e', 'line-style': 'dashed' } },
  { selector: 'edge[kind = "IMPORTS_FROM"]',style: { 'line-color': '#3b82f6', 'target-arrow-color': '#3b82f6', 'line-style': 'dotted' } },
  { selector: '.highlighted', style: { 'background-color': '#6366f1', 'border-color': '#818cf8', 'border-width': 3 } },
];

function initCytoscape(cyNodes, cyEdges) {
  if (cy) cy.destroy();

  // Phase 1 — register all nodes first so edge validation won't fail.
  cy = cytoscape({
    container: $('#cy'),
    elements: cyNodes,
    style: CY_STYLE,
    layout: { name: 'preset' },   // positions calculated in phase 3
  });

  // Phase 2 — add only edges whose both endpoints exist in the cy instance.
  // This silently drops "orphaned" edges (e.g. CALLS to unresolved externals).
  const safeEdges = cyEdges.filter(
    e => cy.getElementById(e.data.source).length > 0 &&
         cy.getElementById(e.data.target).length > 0
  );
  if (safeEdges.length < cyEdges.length) {
    console.debug(`Graph: dropped ${cyEdges.length - safeEdges.length} orphaned edge(s).`);
  }
  cy.add(safeEdges);

  // Phase 3 — run layout then fit the viewport.
  // Use dagre if available, fall back to cose.
  const layoutName = (typeof cytoscapeDagre !== 'undefined' || cy.layout({ name: 'dagre' })) ? 'dagre' : 'cose';
  try {
    cy.layout({ name: 'dagre', rankDir: 'LR', nodeSep: 40, rankSep: 80, animate: false }).run();
  } catch (_) {
    cy.layout({ name: 'cose', animate: false }).run();
  }

  // Resize forces Cytoscape to re-measure the container in case it was
  // zero-sized during initialization (common with flexbox containers).
  cy.resize();
  cy.fit(undefined, 30);

  cy.on('tap', 'node', e => showNodePanel(e.target));
  cy.on('tap', e => { if (e.target === cy) hideNodePanel(); });
}

async function loadGraphFull() {
  $('#cy').innerHTML = '<div style="padding:20px;color:#8892aa">Loading graph…</div>';

  const [findResult, nodeResult, edgeResult] = await Promise.allSettled([
    apiFetch('/api/findings?limit=5000'),
    apiFetch('/api/graph/nodes?limit=2000'),
    apiFetch('/api/graph/edges?limit=10000'),
  ]);

  // Findings failure must not block graph rendering
  if (findResult.status === 'fulfilled') {
    allFindings = findResult.value.findings || [];
    buildFindingsNodeSet();
  } else {
    console.warn('Findings unavailable:', findResult.reason?.message);
  }

  if (nodeResult.status === 'rejected') {
    $('#cy').innerHTML = `<div style="padding:20px;color:#ef4444">Failed to load nodes: ${nodeResult.reason?.message}</div>`;
    return;
  }

  const nodes = nodeResult.value?.nodes ?? [];
  const edges = edgeResult.status === 'fulfilled' ? (edgeResult.value?.edges ?? []) : [];

  if (nodes.length === 0) {
    $('#cy').innerHTML = '<div style="padding:20px;color:#8892aa">No nodes found. Run <code>graphsast scan &lt;target&gt;</code> first.</div>';
    return;
  }

  $('#cy').innerHTML = '';   // clear loading message before Cytoscape takes over
  _allNodes = nodes;
  renderFileTree(nodes);
  initCytoscape(buildCyNodes(nodes), buildCyEdges(edges));
}

async function loadNeighborhood(qualifiedName, depth) {
  try {
    const data = await apiFetch(
      `/api/graph/neighborhood?qualified_name=${encodeURIComponent(qualifiedName)}&depth=${depth}`
    );
    initCytoscape(buildCyNodes(data.nodes), buildCyEdges(data.edges));
    const root = cy.getElementById(qualifiedName);
    if (root.length) {
      root.addClass('highlighted');
      cy.animate({ fit: { eles: root, padding: 100 }, duration: 400 });
    }
  } catch (e) {
    console.error('loadNeighborhood', e);
  }
}

function buildFindingsNodeSet() {
  findingsWithNodes.clear();
  allFindings.forEach(f => {
    if (f.llm_verdict !== 'FALSE_POSITIVE') findingsWithNodes.add(f.file_path);
  });
}

// ── Node detail panel ──────────────────────────────────────────────────────
let _panelNode = null;   // currently displayed node data

function showNodePanel(node) {
  const d = node.data();
  _panelNode = d;
  const panel = $('#node-panel');
  $('#panel-title').textContent = d.label || d.name || d.id;

  // Populate Info tab
  const nodeFindings = allFindings.filter(
    f => f.file_path === d.file_path && f.llm_verdict !== 'FALSE_POSITIVE'
  );
  $('#panel-meta').innerHTML = `
    <div class="panel-field"><label>Kind</label><value>${escHtml(d.kind)}</value></div>
    <div class="panel-field"><label>Qualified Name</label><value>${escHtml(d.qualified_name)}</value></div>
    <div class="panel-field"><label>File</label><value title="${escHtml(d.file_path)}">${escHtml(shortPath(d.file_path, 50))}</value></div>
    <div class="panel-field"><label>Lines</label><value>${d.line_start || '—'} – ${d.line_end || '—'}</value></div>
    ${d.params      ? `<div class="panel-field"><label>Params</label><value>${escHtml(d.params)}</value></div>` : ''}
    ${d.return_type ? `<div class="panel-field"><label>Returns</label><value>${escHtml(d.return_type)}</value></div>` : ''}
    ${nodeFindings.length ? `
      <div class="panel-section">Findings in this file (${nodeFindings.length})</div>
      <ul class="panel-list" id="panel-findings-list">
        ${nodeFindings.map(f => `
          <li data-fp="${escHtml(f.fingerprint)}">
            <span class="${sevClass(f.severity)}">${f.severity}</span> ${escHtml(f.title)}
          </li>`).join('')}
      </ul>` : ''}
    <div style="margin-top:12px">
      <button class="btn-sm" onclick="loadNeighborhood('${escHtml(d.qualified_name)}', parseInt($('#depth-select').value))">
        Focus neighborhood
      </button>
    </div>
  `;

  // Show panel + resize handle, switch to Info tab, then load source
  panel.classList.remove('hidden');
  $('#panel-resize-handle').classList.remove('hidden');
  switchPanelTab('source');   // auto-open source tab on click
  loadSourceCode(d);
}

function hideNodePanel() {
  $('#node-panel').classList.add('hidden');
  $('#panel-resize-handle').classList.add('hidden');
  _panelNode = null;
}
$('#panel-close').addEventListener('click', hideNodePanel);

// Delegated click for findings listed inside the node panel
$('#panel-meta').addEventListener('click', e => {
  const li = e.target.closest('li[data-fp]');
  if (!li) return;
  const finding = allFindings.find(f => f.fingerprint === li.dataset.fp);
  if (finding) openFindingModal(finding);
});

// ── Panel tab switching ────────────────────────────────────────────────────
$$('.panel-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    switchPanelTab(btn.dataset.tab);
    if (btn.dataset.tab === 'source' && _panelNode) loadSourceCode(_panelNode);
  });
});

function switchPanelTab(name) {
  $$('.panel-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $('#panel-meta').style.display    = (name === 'meta')   ? 'block' : 'none';
  $('#panel-source').style.display  = (name === 'source') ? 'flex'  : 'none';
}

// ── Source code display ────────────────────────────────────────────────────
async function loadSourceCode(d) {
  const sourceEl  = $('#source-code');
  const loadingEl = $('#source-loading');

  if (!d.file_path) {
    sourceEl.innerHTML = '<div style="padding:12px;color:#8892aa;font-style:italic">No file path on this node.</div>';
    return;
  }

  loadingEl.style.display = 'block';
  sourceEl.innerHTML = '';

  try {
    const params = new URLSearchParams({
      file_path:  d.file_path,
      line_start: d.line_start || 1,
      line_end:   d.line_end   || d.line_start || 1,
      context:    3,
    });
    const data = await apiFetch(`/api/graph/source?${params}`);
    renderSource(data);
  } catch (e) {
    sourceEl.innerHTML = `<div style="padding:12px;color:#ef4444">Failed: ${escHtml(e.message)}</div>`;
  } finally {
    loadingEl.style.display = 'none';
  }
}

function renderSource(data) {
  const { lines, highlight_start, highlight_end, language } = data;

  // Build a table: line-number gutter | code
  const rows = lines.map(({ number, text }) => {
    const isHighlighted = number >= highlight_start && number <= highlight_end;
    const rowClass = isHighlighted ? ' class="hl-line"' : '';
    return `<tr${rowClass}>` +
      `<td class="ln">${number}</td>` +
      `<td class="lc">${escHtml(text)}</td>` +
      `</tr>`;
  }).join('');

  const lang = language || 'plaintext';
  $('#source-code').innerHTML =
    `<div class="source-header">${escHtml(data.file_path.split('/').pop())} · lines ${highlight_start}–${highlight_end}</div>` +
    `<div class="source-scroll"><table class="source-table"><tbody>${rows}</tbody></table></div>`;

  // Apply highlight.js to each code cell
  $$('#source-code .lc').forEach(cell => {
    if (window.hljs) {
      const result = hljs.highlight(cell.textContent, { language: lang, ignoreIllegals: true });
      cell.innerHTML = result.value;
    }
  });

  // Scroll the first highlighted line into view
  const firstHl = $('#source-code .hl-line');
  if (firstHl) firstHl.scrollIntoView({ block: 'center', behavior: 'smooth' });
}

// ── Graph toolbar ──────────────────────────────────────────────────────────
$('#btn-search-node').addEventListener('click', async () => {
  const q = $('#graph-search').value.trim();
  if (!q) return;
  try {
    const data = await apiFetch(`/api/graph/search?q=${encodeURIComponent(q)}&limit=1`);
    if (!data.results.length) { alert('Node not found'); return; }
    await loadNeighborhood(data.results[0].qualified_name, parseInt($('#depth-select').value));
  } catch (e) { console.error(e); }
});
$('#graph-search').addEventListener('keydown', e => { if (e.key === 'Enter') $('#btn-search-node').click(); });
$('#btn-fit').addEventListener('click', () => cy && cy.fit());
$('#btn-reset-graph').addEventListener('click', () => loadGraphFull());
$('#toggle-tests').addEventListener('change', () => loadGraphFull());
$('#toggle-files').addEventListener('change', () => loadGraphFull());

// ── Findings view ──────────────────────────────────────────────────────────
// Track the currently rendered set so event delegation can look up by fingerprint
let _renderedFindings = [];

async function loadFindings(params = '') {
  try {
    const data = await apiFetch(`/api/findings?limit=1000${params}`);
    allFindings = data.findings || [];
    buildFindingsNodeSet();
    renderFindings(allFindings);
  } catch (e) {
    console.error('loadFindings', e);
    $('#findings-count').textContent = 'Failed to load findings.';
  }
}

function renderFindings(findings) {
  _renderedFindings = findings;
  $('#findings-count').textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''}`;
  // Use data-fp (fingerprint) instead of embedding JSON in onclick —
  // single quotes inside finding text would break onclick='...' attributes.
  $('#findings-tbody').innerHTML = findings.map(f => `
    <tr data-fp="${escHtml(f.fingerprint)}" style="cursor:pointer">
      <td><span class="${sevClass(f.severity)}">${escHtml(f.severity)}</span></td>
      <td>${escHtml(f.title)}</td>
      <td class="file-cell" title="${escHtml(f.file_path)}">${escHtml(shortPath(f.file_path))}:${f.line_start}</td>
      <td class="rule-cell" title="${escHtml(f.rule_id)}">${escHtml(f.rule_id.split('.').pop())}</td>
      <td><span class="${verdClass(f.llm_verdict)}">${verdLabel(f.llm_verdict)}</span></td>
      <td>${f.llm_cvss_score != null ? Number(f.llm_cvss_score).toFixed(1) : '—'}</td>
      <td>${escHtml(f.source) || 'semgrep'}</td>
    </tr>
  `).join('');
}

// Single delegated listener — no inline onclick needed
$('#findings-tbody').addEventListener('click', e => {
  const row = e.target.closest('tr[data-fp]');
  if (!row) return;
  const finding = _renderedFindings.find(f => f.fingerprint === row.dataset.fp);
  if (finding) openFindingModal(finding);
});

$('#btn-apply-filters').addEventListener('click', applyFindingsFilters);
$('#btn-clear-filters').addEventListener('click', () => {
  $('#findings-search').value = '';
  $('#filter-severity').value = '';
  $('#filter-verdict').value = '';
  $('#filter-source').value = '';
  renderFindings(allFindings);
});

function applyFindingsFilters() {
  const sev  = $('#filter-severity').value;
  const verd = $('#filter-verdict').value;
  const src  = $('#filter-source').value;
  const q    = $('#findings-search').value.toLowerCase();
  let filtered = allFindings;
  if (sev)  filtered = filtered.filter(f => f.severity === sev);
  if (verd === 'UNANALYSED') filtered = filtered.filter(f => !f.llm_verdict);
  else if (verd) filtered = filtered.filter(f => f.llm_verdict === verd);
  if (src)  filtered = filtered.filter(f => f.source === src);
  if (q)    filtered = filtered.filter(f =>
    (f.file_path||'').toLowerCase().includes(q) ||
    (f.rule_id||'').toLowerCase().includes(q) ||
    (f.title||'').toLowerCase().includes(q) ||
    (f.message||'').toLowerCase().includes(q)
  );
  renderFindings(filtered);
}
$('#findings-search').addEventListener('keydown', e => { if (e.key === 'Enter') applyFindingsFilters(); });

// ── Finding modal ──────────────────────────────────────────────────────────
function openFindingModal(finding) {
  $('#modal-title').innerHTML =
    `<span class="${sevClass(finding.severity)}">${escHtml(finding.severity)}</span>&nbsp;${escHtml(finding.title)}`;

  const cvss = finding.llm_cvss_score != null ? Number(finding.llm_cvss_score).toFixed(1) : '—';
  $('#modal-body').innerHTML = `
    <div class="modal-section">
      <div class="meta-grid">
        <div class="meta-item"><label>Rule</label><value>${escHtml(finding.rule_id)}</value></div>
        <div class="meta-item"><label>CWE</label><value>${escHtml(finding.cwe_id) || '—'}</value></div>
        <div class="meta-item"><label>File</label><value>${escHtml(finding.file_path)}:${finding.line_start}</value></div>
        <div class="meta-item"><label>Verdict</label><value><span class="${verdClass(finding.llm_verdict)}">${verdLabel(finding.llm_verdict)}</span></value></div>
        <div class="meta-item"><label>CVSS</label><value>${cvss}</value></div>
        <div class="meta-item"><label>Vector</label><value>${escHtml(finding.llm_cvss_vector) || '—'}</value></div>
        <div class="meta-item"><label>First seen</label><value>${escHtml(finding.first_seen_at) || '—'}</value></div>
        <div class="meta-item"><label>Source</label><value>${escHtml(finding.source) || 'semgrep'}</value></div>
      </div>
    </div>
    ${finding.snippet ? `<div class="modal-section"><h4>Code Snippet</h4><pre>${escHtml(finding.snippet)}</pre></div>` : ''}
    ${finding.message ? `<div class="modal-section"><h4>Semgrep Message</h4><p>${escHtml(finding.message)}</p></div>` : ''}
    ${finding.llm_description ? `<div class="modal-section"><h4>Description</h4><p>${escHtml(finding.llm_description)}</p></div>` : ''}
    ${finding.llm_reasoning   ? `<div class="modal-section"><h4>LLM Reasoning</h4><p>${escHtml(finding.llm_reasoning)}</p></div>` : ''}
    ${finding.llm_poc         ? `<div class="modal-section"><h4>Proof of Concept</h4><pre>${escHtml(finding.llm_poc)}</pre></div>` : ''}
    <div class="modal-section">
      <button class="btn-sm jump-to-graph" data-filepath="${escHtml(finding.file_path)}">View in graph</button>
    </div>
  `;
  $('#finding-modal').classList.remove('hidden');
}

function jumpToGraphNode(filePath) {
  $('#modal-close').click();
  $('[data-view="graph"]').click();
  if (!cy) return;
  const match = cy.nodes().filter(n => n.data('file_path') === filePath);
  if (match.length) {
    cy.fit(match, 80);
    match.first().emit('tap');
  }
}

$('#modal-close').addEventListener('click', () => $('#finding-modal').classList.add('hidden'));
$('#modal-backdrop').addEventListener('click', () => $('#finding-modal').classList.add('hidden'));
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#finding-modal').classList.add('hidden'); });
$('#modal-body').addEventListener('click', e => {
  const btn = e.target.closest('.jump-to-graph');
  if (btn) jumpToGraphNode(btn.dataset.filepath);
});

// ── Scan runs view ─────────────────────────────────────────────────────────
async function loadRuns() {
  try {
    const data = await apiFetch('/api/runs');
    $('#runs-tbody').innerHTML = (data.runs || []).map(r => {
      const isHunt = r.semgrep_config === 'hunter';
      const typeBadge = isHunt
        ? '<span class="badge-hunt">Hunt</span>'
        : '<span class="badge-semgrep">Semgrep</span>';
      const findings = isHunt ? (r.new_findings || 0) : (r.semgrep_total || 0);
      return `<tr class="${isHunt ? 'run-hunt' : ''}">
        <td>#${r.id}</td>
        <td>${typeBadge}</td>
        <td>${(r.started_at || '').slice(0, 19)}</td>
        <td title="${escHtml(r.target)}">${escHtml(shortPath(r.target, 40))}</td>
        <td>${escHtml(r.model) || '—'}</td>
        <td>${findings}</td>
        <td style="color:var(--confirmed)">${r.confirmed || 0}</td>
        <td style="color:var(--fp)">${r.false_positives || 0}</td>
        <td>${r.new_findings || 0}</td>
        <td>${r.recurring || 0}</td>
      </tr>`;
    }).join('');
  } catch (e) { console.error('loadRuns', e); }
}

// ── File tree ───────────────────────────────────────────────────────────────
function stripTarget(fp) {
  if (!fp) return fp;
  if (_targetPath && fp.startsWith(_targetPath)) return fp.slice(_targetPath.length);
  return fp;
}

function buildFileTree(nodes) {
  const filePaths = [...new Set(nodes.map(n => n.file_path).filter(Boolean))].sort();
  const root = { dirs: {}, files: [] };
  for (const fp of filePaths) {
    const parts = stripTarget(fp).split('/').filter(Boolean);
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!node.dirs[parts[i]]) node.dirs[parts[i]] = { dirs: {}, files: [] };
      node = node.dirs[parts[i]];
    }
    node.files.push({ name: parts[parts.length - 1] || fp, fullPath: fp });
  }
  return root;
}

let _treeUid = 0;
function renderTreeNode(node, depth) {
  const pad = depth * 14;
  let html = '';
  for (const [name, child] of Object.entries(node.dirs).sort(([a], [b]) => a.localeCompare(b))) {
    const uid = `td${_treeUid++}`;
    const open = depth === 0;
    html += `<div class="tree-dir-label" style="padding-left:${pad}px" data-toggle="${uid}" data-open="${open}">` +
      `<span class="tree-arrow">${open ? '▾' : '▸'}</span>${escHtml(name)}/</div>` +
      `<div id="${uid}"${open ? '' : ' style="display:none"'}>${renderTreeNode(child, depth + 1)}</div>`;
  }
  for (const { name, fullPath } of node.files.sort((a, b) => a.name.localeCompare(b.name))) {
    html += `<div class="tree-file-item" style="padding-left:${pad + 14}px" ` +
      `data-filepath="${escHtml(fullPath)}" title="${escHtml(fullPath)}">${escHtml(name)}</div>`;
  }
  return html;
}

function renderFileTree(nodes) {
  const el = $('#file-tree');
  if (!el) return;
  _treeUid = 0;
  el.innerHTML = renderTreeNode(buildFileTree(nodes), 0);
}

$('#file-tree').addEventListener('click', e => {
  // Toggle directory
  const dir = e.target.closest('[data-toggle]');
  if (dir) {
    const child = document.getElementById(dir.dataset.toggle);
    const open = dir.dataset.open === 'true';
    if (child) { child.style.display = open ? 'none' : ''; }
    dir.dataset.open = (!open).toString();
    dir.querySelector('.tree-arrow').textContent = open ? '▸' : '▾';
    return;
  }
  // Click file
  const file = e.target.closest('[data-filepath]');
  if (file) {
    $$('.tree-file-item.active').forEach(el => el.classList.remove('active'));
    file.classList.add('active');
    highlightFileInGraph(file.dataset.filepath);
  }
});

function highlightFileInGraph(filePath) {
  if (!cy) return;
  cy.nodes().removeClass('highlighted');
  const matched = cy.nodes().filter(n => n.data('file_path') === filePath);
  if (matched.length) {
    matched.addClass('highlighted');
    cy.fit(matched, 60);
  }
}

$('#btn-toggle-filetree').addEventListener('click', () => {
  const panel = $('#file-tree-panel');
  const hidden = panel.style.display === 'none';
  panel.style.display = hidden ? '' : 'none';
  if (cy) cy.resize();
});

// ── Panel resize ────────────────────────────────────────────────────────────
(function () {
  const handle = document.getElementById('panel-resize-handle');
  const panel  = document.getElementById('node-panel');
  let active = false, startX = 0, startW = 0;

  handle.addEventListener('mousedown', function (e) {
    active  = true;
    startX  = e.clientX;
    startW  = panel.getBoundingClientRect().width;
    handle.classList.add('dragging');
    document.body.style.cursor     = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  window.addEventListener('mousemove', function (e) {
    if (!active) return;
    const delta = startX - e.clientX;   // drag left → positive → wider panel
    const newW  = Math.max(260, Math.min(820, startW + delta));
    panel.style.width = newW + 'px';
  });

  window.addEventListener('mouseup', function () {
    if (!active) return;
    active = false;
    handle.classList.remove('dragging');
    document.body.style.cursor     = '';
    document.body.style.userSelect = '';
    if (cy) cy.resize();
  });
})();

// ── Boot ───────────────────────────────────────────────────────────────────
(async () => {
  await loadStats();
  await loadGraphFull();
})();
