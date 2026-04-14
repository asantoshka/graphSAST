/* GraphSAST Web UI — Cytoscape.js graph + findings dashboard */

// ── State ──────────────────────────────────────────────────────────────────
let cy = null;
let allFindings = [];
let findingsWithNodes = new Set(); // qualified_names that have findings

// ── Utilities ──────────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

async function apiFetch(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error ${res.status}: ${url}`);
  return res.json();
}

function sevClass(sev) {
  return `sev sev-${sev || 'UNKNOWN'}`;
}

function verdClass(verd) {
  return `verd verd-${verd || 'null'}`;
}

function verdLabel(verd) {
  if (!verd) return '–';
  return { CONFIRMED: 'Confirmed', FALSE_POSITIVE: 'False Pos.', NEEDS_REVIEW: 'Needs Review' }[verd] || verd;
}

function shortPath(p, len = 40) {
  if (!p || p.length <= len) return p || '—';
  return '…' + p.slice(-(len - 1));
}

// ── View switching ─────────────────────────────────────────────────────────
$$('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.nav-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const view = btn.dataset.view;
    $$('.view').forEach(v => v.classList.remove('active'));
    $(`#view-${view}`).classList.add('active');
    if (view === 'findings' && allFindings.length === 0) loadFindings();
    if (view === 'runs') loadRuns();
    if (view === 'graph' && cy) cy.resize();
  });
});

// ── Stats bar ──────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const data = await apiFetch('/api/stats');
    $('#target-label').textContent = data.target || '';
    $('#stat-nodes').textContent = `${data.graph.total_nodes.toLocaleString()} nodes`;
    $('#stat-edges').textContent = `${data.graph.total_edges.toLocaleString()} edges`;
    const bySev = data.findings.by_severity || {};
    $('#stat-critical').textContent = `${bySev.CRITICAL || 0} CRITICAL`;
    $('#stat-high').textContent = `${bySev.HIGH || 0} HIGH`;
    $('#stat-medium').textContent = `${bySev.MEDIUM || 0} MEDIUM`;
    $('#stat-low').textContent = `${bySev.LOW || 0} LOW`;
  } catch (e) {
    console.error('loadStats', e);
  }
}

// ── Graph view ─────────────────────────────────────────────────────────────
const KIND_COLORS = {
  File: '#64748b',
  Class: '#22c55e',
  Function: '#f97316',
  Type: '#a78bfa',
  Test: '#3b82f6',
};

function nodeColor(kind) {
  return KIND_COLORS[kind] || '#94a3b8';
}

function buildCyElements(nodes, edges) {
  const showTests = $('#toggle-tests').checked;
  const showFiles = $('#toggle-files').checked;

  const filteredNodes = nodes.filter(n => {
    if (!showTests && n.is_test) return false;
    if (!showFiles && n.kind === 'File') return false;
    return true;
  });
  const nodeIds = new Set(filteredNodes.map(n => n.qualified_name));

  const cyNodes = filteredNodes.map(n => ({
    data: {
      id: n.qualified_name,
      label: n.name,
      kind: n.kind,
      color: nodeColor(n.kind),
      hasFinding: findingsWithNodes.has(n.qualified_name),
      ...n,
    },
  }));

  const cyEdges = edges
    .filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))
    .map(e => ({
      data: {
        id: `e-${e.id}`,
        source: e.source,
        target: e.target,
        kind: e.kind,
      },
    }));

  return [...cyNodes, ...cyEdges];
}

function initCytoscape(elements) {
  if (cy) cy.destroy();

  cy = cytoscape({
    container: $('#cy'),
    elements,
    style: [
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
      {
        selector: 'node[kind = "File"]',
        style: { shape: 'rectangle', width: '18px', height: '18px' },
      },
      {
        selector: 'node[kind = "Class"]',
        style: { shape: 'diamond', width: '26px', height: '26px' },
      },
      {
        selector: 'node[?hasFinding]',
        style: {
          'border-width': 3,
          'border-color': '#ef4444',
          'width': '26px',
          'height': '26px',
        },
      },
      {
        selector: 'node:selected',
        style: { 'border-width': 3, 'border-color': '#6366f1' },
      },
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
      {
        selector: 'edge[kind = "CALLS"]',
        style: { 'line-color': '#4b5563', 'target-arrow-color': '#4b5563' },
      },
      {
        selector: 'edge[kind = "INHERITS"]',
        style: {
          'line-color': '#22c55e', 'target-arrow-color': '#22c55e',
          'line-style': 'dashed',
        },
      },
      {
        selector: 'edge[kind = "IMPORTS_FROM"]',
        style: {
          'line-color': '#3b82f6', 'target-arrow-color': '#3b82f6',
          'line-style': 'dotted',
        },
      },
      {
        selector: '.highlighted',
        style: { 'background-color': '#6366f1', 'border-color': '#818cf8', 'border-width': 3 },
      },
    ],
    layout: {
      name: 'dagre',
      rankDir: 'LR',
      nodeSep: 40,
      rankSep: 80,
      animate: false,
    },
    wheelSensitivity: 0.3,
  });

  cy.on('tap', 'node', (e) => showNodePanel(e.target));
  cy.on('tap', (e) => {
    if (e.target === cy) hideNodePanel();
  });
}

async function loadGraphFull() {
  try {
    // Load findings first so we can mark nodes
    const findData = await apiFetch('/api/findings?limit=5000');
    allFindings = findData.findings || [];
    buildFindingsNodeSet();

    const [nodeData, edgeData] = await Promise.all([
      apiFetch('/api/graph/nodes?limit=2000'),
      apiFetch('/api/graph/edges?limit=10000'),
    ]);
    const elements = buildCyElements(nodeData.nodes, edgeData.edges);
    initCytoscape(elements);
  } catch (e) {
    console.error('loadGraphFull', e);
    $('#cy').innerHTML = `<div style="padding:20px;color:#ef4444">Failed to load graph: ${e.message}</div>`;
  }
}

async function loadNeighborhood(qualifiedName, depth) {
  try {
    const data = await apiFetch(
      `/api/graph/neighborhood?qualified_name=${encodeURIComponent(qualifiedName)}&depth=${depth}`
    );
    const elements = buildCyElements(data.nodes, data.edges);
    initCytoscape(elements);
    // Highlight root node
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
  // Map file_path + line_start to qualified names via the API is complex;
  // instead we mark by file_path so at least file nodes light up
  allFindings.forEach(f => {
    if (f.llm_verdict !== 'FALSE_POSITIVE') {
      findingsWithNodes.add(f.file_path);
    }
  });
}

// ── Node detail panel ──────────────────────────────────────────────────────
function showNodePanel(node) {
  const data = node.data();
  const panel = $('#node-panel');
  const body = $('#panel-body');
  $('#panel-title').textContent = data.name;

  // Findings for this file
  const nodeFindings = allFindings.filter(
    f => f.file_path === data.file_path && f.llm_verdict !== 'FALSE_POSITIVE'
  );

  body.innerHTML = `
    <div class="panel-field">
      <label>Kind</label>
      <value>${data.kind}</value>
    </div>
    <div class="panel-field">
      <label>Qualified Name</label>
      <value>${data.qualified_name}</value>
    </div>
    <div class="panel-field">
      <label>File</label>
      <value>${shortPath(data.file_path, 50)}</value>
    </div>
    <div class="panel-field">
      <label>Lines</label>
      <value>${data.line_start || '—'} – ${data.line_end || '—'}</value>
    </div>
    ${data.params ? `<div class="panel-field"><label>Params</label><value>${data.params}</value></div>` : ''}
    ${data.return_type ? `<div class="panel-field"><label>Returns</label><value>${data.return_type}</value></div>` : ''}
    ${nodeFindings.length ? `
      <div class="panel-section">Findings (${nodeFindings.length})</div>
      <ul class="panel-list">
        ${nodeFindings.map(f => `
          <li onclick="openFindingModal(${JSON.stringify(f).replace(/"/g, '&quot;')})">
            <span class="${sevClass(f.severity)}">${f.severity}</span>
            ${f.title}
          </li>
        `).join('')}
      </ul>
    ` : ''}
    <div style="margin-top:12px">
      <button class="btn-sm" onclick="loadNeighborhood('${data.qualified_name}', parseInt($('#depth-select').value))">
        Focus neighborhood
      </button>
    </div>
  `;

  panel.classList.remove('hidden');
}

function hideNodePanel() {
  $('#node-panel').classList.add('hidden');
}

$('#panel-close').addEventListener('click', hideNodePanel);

// ── Graph toolbar ──────────────────────────────────────────────────────────
$('#btn-search-node').addEventListener('click', async () => {
  const q = $('#graph-search').value.trim();
  if (!q) return;
  try {
    const data = await apiFetch(`/api/graph/search?q=${encodeURIComponent(q)}&limit=1`);
    if (data.results.length === 0) { alert('Node not found'); return; }
    const qn = data.results[0].qualified_name;
    const depth = parseInt($('#depth-select').value);
    await loadNeighborhood(qn, depth);
  } catch (e) { console.error(e); }
});

$('#graph-search').addEventListener('keydown', e => {
  if (e.key === 'Enter') $('#btn-search-node').click();
});

$('#btn-fit').addEventListener('click', () => cy && cy.fit());
$('#btn-reset-graph').addEventListener('click', () => loadGraphFull());

$('#toggle-tests').addEventListener('change', () => loadGraphFull());
$('#toggle-files').addEventListener('change', () => loadGraphFull());

// ── Findings view ──────────────────────────────────────────────────────────
async function loadFindings(params = '') {
  try {
    const data = await apiFetch(`/api/findings?limit=1000${params}`);
    allFindings = data.findings || [];
    buildFindingsNodeSet();
    renderFindings(allFindings);
  } catch (e) {
    console.error('loadFindings', e);
  }
}

function renderFindings(findings) {
  $('#findings-count').textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''}`;
  const tbody = $('#findings-tbody');
  tbody.innerHTML = findings.map(f => `
    <tr onclick="openFindingModal(${escapeJsonAttr(f)})">
      <td><span class="${sevClass(f.severity)}">${f.severity}</span></td>
      <td>${escHtml(f.title)}</td>
      <td class="file-cell" title="${escHtml(f.file_path)}">
        ${escHtml(shortPath(f.file_path))}:${f.line_start}
      </td>
      <td class="rule-cell" title="${escHtml(f.rule_id)}">${escHtml(f.rule_id.split('.').pop())}</td>
      <td><span class="${verdClass(f.llm_verdict)}">${verdLabel(f.llm_verdict)}</span></td>
      <td>${f.llm_cvss_score != null ? f.llm_cvss_score.toFixed(1) : '—'}</td>
      <td>${f.source || 'semgrep'}</td>
    </tr>
  `).join('');
}

function escHtml(s) {
  if (!s) return '';
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeJsonAttr(obj) {
  return JSON.stringify(obj).replace(/"/g, '&quot;');
}

// Filter bar
$('#btn-apply-filters').addEventListener('click', applyFindingsFilters);
$('#btn-clear-filters').addEventListener('click', () => {
  $('#findings-search').value = '';
  $('#filter-severity').value = '';
  $('#filter-verdict').value = '';
  $('#filter-source').value = '';
  loadFindings();
});

function applyFindingsFilters() {
  const sev = $('#filter-severity').value;
  const verd = $('#filter-verdict').value;
  const src = $('#filter-source').value;
  const q = $('#findings-search').value.toLowerCase();

  let filtered = allFindings;
  if (sev) filtered = filtered.filter(f => f.severity === sev);
  if (verd === 'UNANALYSED') {
    filtered = filtered.filter(f => !f.llm_verdict);
  } else if (verd) {
    filtered = filtered.filter(f => f.llm_verdict === verd);
  }
  if (src) filtered = filtered.filter(f => f.source === src);
  if (q) {
    filtered = filtered.filter(f =>
      (f.file_path || '').toLowerCase().includes(q) ||
      (f.rule_id || '').toLowerCase().includes(q) ||
      (f.title || '').toLowerCase().includes(q) ||
      (f.message || '').toLowerCase().includes(q)
    );
  }
  renderFindings(filtered);
}

$('#findings-search').addEventListener('keydown', e => {
  if (e.key === 'Enter') applyFindingsFilters();
});

// ── Finding modal ──────────────────────────────────────────────────────────
function openFindingModal(finding) {
  if (typeof finding === 'string') finding = JSON.parse(finding.replace(/&quot;/g, '"'));

  $('#modal-title').innerHTML = `
    <span class="${sevClass(finding.severity)}">${finding.severity}</span>
    &nbsp;${escHtml(finding.title)}
  `;

  const cvssScore = finding.llm_cvss_score != null ? finding.llm_cvss_score.toFixed(1) : '—';

  $('#modal-body').innerHTML = `
    <div class="modal-section">
      <div class="meta-grid">
        <div class="meta-item">
          <label>Rule</label>
          <value>${escHtml(finding.rule_id)}</value>
        </div>
        <div class="meta-item">
          <label>CWE</label>
          <value>${escHtml(finding.cwe_id) || '—'}</value>
        </div>
        <div class="meta-item">
          <label>File</label>
          <value>${escHtml(finding.file_path)}:${finding.line_start}</value>
        </div>
        <div class="meta-item">
          <label>Verdict</label>
          <value><span class="${verdClass(finding.llm_verdict)}">${verdLabel(finding.llm_verdict)}</span></value>
        </div>
        <div class="meta-item">
          <label>CVSS Score</label>
          <value>${cvssScore}</value>
        </div>
        <div class="meta-item">
          <label>CVSS Vector</label>
          <value>${escHtml(finding.llm_cvss_vector) || '—'}</value>
        </div>
        <div class="meta-item">
          <label>First seen</label>
          <value>${finding.first_seen_at || '—'}</value>
        </div>
        <div class="meta-item">
          <label>Source</label>
          <value>${finding.source || 'semgrep'}</value>
        </div>
      </div>
    </div>

    ${finding.snippet ? `
    <div class="modal-section">
      <h4>Code Snippet</h4>
      <pre>${escHtml(finding.snippet)}</pre>
    </div>` : ''}

    ${finding.llm_description ? `
    <div class="modal-section">
      <h4>Description</h4>
      <p>${escHtml(finding.llm_description)}</p>
    </div>` : ''}

    ${finding.llm_reasoning ? `
    <div class="modal-section">
      <h4>LLM Reasoning</h4>
      <p>${escHtml(finding.llm_reasoning)}</p>
    </div>` : ''}

    ${finding.llm_poc ? `
    <div class="modal-section">
      <h4>Proof of Concept</h4>
      <pre>${escHtml(finding.llm_poc)}</pre>
    </div>` : ''}

    ${finding.message ? `
    <div class="modal-section">
      <h4>Semgrep Message</h4>
      <p>${escHtml(finding.message)}</p>
    </div>` : ''}

    <div class="modal-section jump-to-graph">
      <button class="btn-sm" onclick="jumpToGraphNode('${escHtml(finding.file_path)}')">
        View in graph
      </button>
    </div>
  `;

  $('#finding-modal').classList.remove('hidden');
}

function jumpToGraphNode(filePath) {
  // Switch to graph view, search for file node
  $('#modal-close').click();
  $$('.nav-btn').forEach(b => b.classList.remove('active'));
  $('[data-view="graph"]').classList.add('active');
  $$('.view').forEach(v => v.classList.remove('active'));
  $('#view-graph').classList.add('active');
  if (cy) cy.resize();

  // Find a node with this file_path and focus
  const match = cy && cy.nodes().filter(n => n.data('file_path') === filePath);
  if (match && match.length) {
    cy.fit(match, 80);
    match.first().emit('tap');
  } else {
    // Load neighborhood of the file node
    $('#graph-search').value = filePath.split('/').pop().replace(/\.\w+$/, '');
    loadNeighborhood(filePath, 2);
  }
}

$('#modal-close').addEventListener('click', () => $('#finding-modal').classList.add('hidden'));
$('#modal-backdrop').addEventListener('click', () => $('#finding-modal').classList.add('hidden'));
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') $('#finding-modal').classList.add('hidden');
});

// ── Scan runs view ─────────────────────────────────────────────────────────
async function loadRuns() {
  try {
    const data = await apiFetch('/api/runs');
    const tbody = $('#runs-tbody');
    tbody.innerHTML = (data.runs || []).map(r => `
      <tr>
        <td>#${r.id}</td>
        <td>${(r.started_at || '').replace('T', ' ').slice(0, 19)}</td>
        <td title="${escHtml(r.target)}">${escHtml(shortPath(r.target, 40))}</td>
        <td>${escHtml(r.model) || '—'}</td>
        <td>${r.semgrep_total || 0}</td>
        <td style="color:var(--confirmed)">${r.confirmed || 0}</td>
        <td style="color:var(--fp)">${r.false_positives || 0}</td>
        <td>${r.new_findings || 0}</td>
        <td>${r.recurring || 0}</td>
      </tr>
    `).join('');
  } catch (e) {
    console.error('loadRuns', e);
  }
}

// ── Boot ───────────────────────────────────────────────────────────────────
(async () => {
  await loadStats();
  await loadGraphFull();
})();
