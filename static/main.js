const state = {
  selectedFile: null,
  currentReport: null,
  busy: false,
  findingFilter: "all",
};

const elements = {
  dropZone: document.getElementById("dropZone"),
  fileInput: document.getElementById("fileInput"),
  themeToggle: document.getElementById("themeToggle"),
  backToTopButton: document.getElementById("backToTopButton"),
  pickFileButton: document.getElementById("pickFileButton"),
  sampleButton: document.getElementById("sampleButton"),
  analyzeButton: document.getElementById("analyzeButton"),
  downloadJsonButton: document.getElementById("downloadJsonButton"),
  downloadHtmlButton: document.getElementById("downloadHtmlButton"),
  selectedFileName: document.getElementById("selectedFileName"),
  statusLine: document.getElementById("statusLine"),
  resultsSection: document.getElementById("resultsSection"),
  caseSummary: document.getElementById("caseSummary"),
  reportHeadline: document.getElementById("reportHeadline"),
  severityPills: document.getElementById("severityPills"),
  summaryGrid: document.getElementById("summaryGrid"),
  findingsMeta: document.getElementById("findingsMeta"),
  analystSummary: document.getElementById("analystSummary"),
  pivots: document.getElementById("pivots"),
  detections: document.getElementById("detections"),
  suspiciousHosts: document.getElementById("suspiciousHosts"),
  directoryServices: document.getElementById("directoryServices"),
  artifacts: document.getElementById("artifacts"),
  threatIntel: document.getElementById("threatIntel"),
  protocols: document.getElementById("protocols"),
  ports: document.getElementById("ports"),
  hosts: document.getElementById("hosts"),
  flows: document.getElementById("flows"),
  timeline: document.getElementById("timeline"),
  importantFrames: document.getElementById("importantFrames"),
  dns: document.getElementById("dns"),
  http: document.getElementById("http"),
  tls: document.getElementById("tls"),
  kerberos: document.getElementById("kerberos"),
  ldap: document.getElementById("ldap"),
  rpc: document.getElementById("rpc"),
  warnings: document.getElementById("warnings"),
};

function initialize() {
  initializeTheme();
  elements.themeToggle.addEventListener("click", toggleTheme);
  elements.backToTopButton.addEventListener("click", scrollToTop);
  window.addEventListener("scroll", updateBackToTopVisibility, { passive: true });
  updateBackToTopVisibility();
  elements.pickFileButton.addEventListener("click", () => elements.fileInput.click());
  elements.fileInput.addEventListener("change", () => {
    const [file] = elements.fileInput.files;
    if (file) {
      setSelectedFile(file);
    }
  });

  elements.analyzeButton.addEventListener("click", analyzeSelectedFile);
  elements.sampleButton.addEventListener("click", runSampleReport);
  elements.downloadJsonButton.addEventListener("click", downloadJsonReport);
  elements.downloadHtmlButton.addEventListener("click", downloadHtmlReport);

  ["dragenter", "dragover"].forEach((eventName) => {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.dropZone.classList.add("is-dragover");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.dropZone.classList.remove("is-dragover");
    });
  });

  elements.dropZone.addEventListener("drop", (event) => {
    const [file] = event.dataTransfer.files;
    if (file) {
      setSelectedFile(file);
    }
  });
}

function initializeTheme() {
  const storedTheme = window.localStorage.getItem("wireglass-theme");
  const systemPrefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const theme = storedTheme || (systemPrefersDark ? "dark" : "light");
  applyTheme(theme);
}

function applyTheme(theme) {
  const resolvedTheme = theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = resolvedTheme;
  const isDark = resolvedTheme === "dark";
  elements.themeToggle.setAttribute("aria-pressed", String(isDark));
  elements.themeToggle.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
  const icon = elements.themeToggle.querySelector(".theme-toggle__icon");
  const label = elements.themeToggle.querySelector(".theme-toggle__label");
  if (icon) {
    icon.textContent = "";
  }
  if (label) {
    label.textContent = isDark ? "Light" : "Dark";
  }
}

function toggleTheme() {
  const nextTheme = document.body.dataset.theme === "dark" ? "light" : "dark";
  window.localStorage.setItem("wireglass-theme", nextTheme);
  applyTheme(nextTheme);
}

function setSelectedFile(file) {
  state.selectedFile = file;
  elements.selectedFileName.textContent = `${file.name} | ${formatBytes(file.size)}`;
  elements.analyzeButton.disabled = false;
  setStatus(`Ready to analyze ${file.name}.`);
}

function setBusy(isBusy, message) {
  state.busy = isBusy;
  elements.analyzeButton.disabled = isBusy || !state.selectedFile;
  elements.sampleButton.disabled = isBusy;
  elements.pickFileButton.disabled = isBusy;
  elements.downloadJsonButton.disabled = isBusy || !state.currentReport;
  elements.downloadHtmlButton.disabled = isBusy || !state.currentReport;
  if (message) {
    setStatus(message);
  }
}

function setStatus(message) {
  elements.statusLine.textContent = message;
}

function scrollToCaseSummary() {
  if (!elements.caseSummary) {
    return;
  }
  window.setTimeout(() => {
    elements.caseSummary.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 80);
}

function scrollToTop() {
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function updateBackToTopVisibility() {
  if (!elements.backToTopButton) {
    return;
  }
  const shouldShow = window.scrollY > 420;
  elements.backToTopButton.classList.toggle("is-visible", shouldShow);
}

async function analyzeSelectedFile() {
  if (!state.selectedFile || state.busy) {
    return;
  }
  setBusy(true, `Analyzing ${state.selectedFile.name} locally...`);
  try {
    const buffer = await state.selectedFile.arrayBuffer();
    const report = await postCapture(buffer, state.selectedFile.name);
    renderReport(report);
    scrollToCaseSummary();
    setStatus(`Analysis complete for ${state.selectedFile.name}.`);
  } catch (error) {
    setStatus(error.message || "Analysis failed.");
  } finally {
    setBusy(false);
  }
}

async function runSampleReport() {
  if (state.busy) {
    return;
  }
  setBusy(true, "Generating and analyzing the built-in sample capture...");
  try {
    const response = await fetch("/api/sample-report");
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      throw new Error(payload.error || "Sample report failed.");
    }
    state.selectedFile = null;
    elements.selectedFileName.textContent = "Built-in sample capture";
    renderReport(payload.report);
    scrollToCaseSummary();
    setStatus("Sample report generated.");
  } catch (error) {
    setStatus(error.message || "Sample report failed.");
  } finally {
    setBusy(false);
  }
}

async function postCapture(buffer, filename) {
  const response = await fetch(`/api/analyze?filename=${encodeURIComponent(filename)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
    },
    body: buffer,
  });
  const payload = await response.json();
  if (!response.ok || !payload.ok) {
    throw new Error(payload.error || "Upload failed.");
  }
  return payload.report;
}

function renderReport(report) {
  state.currentReport = report;
  elements.resultsSection.classList.remove("hidden");
  elements.downloadJsonButton.disabled = false;
  elements.downloadHtmlButton.disabled = false;

  elements.reportHeadline.textContent = report.summary.headline;
  elements.findingsMeta.textContent =
    `${report.summary.finding_count} findings | ` +
    `${report.artifact_summary.count} artifacts | ` +
    `${report.threat_intel_matches.length} local intel results | ` +
    `risk ${report.summary.risk_score}`;

  renderSeverityPills(report.summary.severity_counts);
  renderSummary(report);
  renderAnalystSummary(report.analyst_summary);
  renderInvestigationShortcuts(report.investigation_shortcuts || {});
  renderDetections(report.detections);
  renderSuspiciousHosts(report.suspicious_hosts);
  renderDirectoryServices(report.directory_services);
  renderArtifacts(report.artifacts, report.artifact_summary);
  renderThreatIntel(report.threat_intel_matches);
  renderProtocols(report.application_protocols, report.layer4_protocols);
  renderPorts(report.top_destination_ports);
  renderHosts(report.top_talkers);
  renderFlows(report.top_flows);
  renderTimeline(report.timeline, report.metadata.capture_started_at_utc);
  renderImportantFrames(report.important_frames);
  renderRecordList(elements.dns, report.dns_queries, formatDnsEntry);
  renderRecordList(elements.http, report.http_events, formatHttpEntry);
  renderRecordList(elements.tls, report.tls_client_hellos, formatTlsEntry);
  renderRecordList(elements.kerberos, report.kerberos_events, formatKerberosEntry);
  renderRecordList(elements.ldap, report.ldap_events, formatLdapEntry);
  renderRpcSection(report.rpc_events, report.smb_events);
  renderWarnings(report.warnings);
}

function renderInvestigationShortcuts(shortcuts) {
  const priority = shortcuts.priority || [];
  if (!priority.length) {
    elements.pivots.innerHTML = `<div class="empty-state">No pivot recommendations were generated for this capture.</div>`;
    return;
  }
  elements.pivots.innerHTML = `
    <div class="shortcut-stack">
      ${priority
        .map(
          (item, index) => `
            <article class="shortcut-card">
              <div class="shortcut-card__index">${index + 1}</div>
              <div>
                <p class="shortcut-card__meta">${escapeHtml(item.kind.replace("_", " "))}</p>
                <div class="shortcut-card__title">
                  <strong>${escapeHtml(item.title || item.indicator || "indicator")}</strong>
                  <span class="severity-tag severity-tag--${normalizeSeverityClass(item.severity)}">${escapeHtml(item.severity)}</span>
                </div>
                <p class="shortcut-card__reason">${escapeHtml(item.reason || "Recommended next pivot.")}</p>
                <div class="finding__details finding__details--tight">
                  <span>${escapeHtml(shortHash(item.indicator || "", 28))}</span>
                </div>
                <div class="link-row">
                  ${(item.links || []).map((link) => buildPivotLink(link.label, link.url)).join("")}
                </div>
              </div>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderSeverityPills(counts) {
  const pills = [];
  if (counts.high) pills.push(`<span class="pill-high">${counts.high} high</span>`);
  if (counts.medium) pills.push(`<span class="pill-medium">${counts.medium} medium</span>`);
  if (counts.low) pills.push(`<span class="pill-low">${counts.low} low</span>`);
  if (!pills.length) pills.push("<span>No detections</span>");
  elements.severityPills.innerHTML = pills.join("");
}

function renderSummary(report) {
  const score = report.summary.risk_score;
  const ringColor = score >= 70 ? "var(--high)" : score >= 40 ? "var(--medium)" : "var(--teal)";
  const metadata = report.metadata;
  const stats = report.stats;
  const artifactSummary = report.artifact_summary;
  const leadArtifact = report.artifacts.find((artifact) => artifact.suspicious) || report.artifacts[0] || null;
  const signal = score >= 70 ? "Escalate" : score >= 40 ? "Review soon" : "Monitor";
  const startLabel = metadata.capture_started_at_utc
    ? new Date(metadata.capture_started_at_utc).toLocaleString()
    : metadata.analyzed_at_utc;
  const captureLinks = metadata.capture_sha256
    ? [
        buildPivotLink("VirusTotal", `https://www.virustotal.com/gui/file/${metadata.capture_sha256}`),
        buildPivotLink("AlienVault OTX", `https://otx.alienvault.com/indicator/file/${metadata.capture_sha256}`),
      ].join("")
    : "";
  const hashRecommendation = leadArtifact
    ? `Recommended: pivot ${leadArtifact.filename} first, then compare the full capture hash.`
    : "Recommended: no artifact hash was recovered, so start with the capture hash and suspicious IP/domain pivots.";
  elements.summaryGrid.innerHTML = `
    <div class="col-12 col-xl-7">
      <article class="summary-hero h-100">
        <div class="summary-hero__copy">
          <p class="summary-hero__eyebrow">Case posture</p>
          <h3>${escapeHtml(report.summary.headline)}</h3>
          <p>${escapeHtml(shorten(metadata.source_name || "capture", 64))} | ${escapeHtml(startLabel || "Unknown start time")}</p>
          <div class="summary-hero__chips">
            <span>${escapeHtml(metadata.capture_format.toUpperCase())}</span>
            <span>${formatDuration(metadata.duration_seconds)}</span>
            <span>${escapeHtml(metadata.linktypes.join(", ") || "unknown linktype")}</span>
            <span>${stats.internal_hosts} internal / ${stats.external_hosts} external</span>
          </div>
        </div>
        <div class="summary-score">
          <div class="risk-orb" style="--risk:${score}; --ring-color:${ringColor};">
            <div class="risk-orb__inner">${score}</div>
          </div>
          <p class="summary-signal">${signal}</p>
        </div>
      </article>
    </div>
    <div class="col-12 col-xl-5">
      <article class="summary-fingerprint h-100">
        <p class="summary-fingerprint__eyebrow">Capture fingerprint</p>
        <h3>Capture SHA-256</h3>
        <div class="hash-value">${escapeHtml(metadata.capture_sha256)}</div>
        <p class="summary-fingerprint__copy">Report v${report.report_version} | ${escapeHtml(hashRecommendation)}</p>
        <div class="summary-fingerprint__links">
          ${captureLinks}
        </div>
      </article>
    </div>
    <div class="col-12 col-md-6 col-xl-3">
      <article class="summary-stat h-100">
        <p class="summary-stat__label">Traffic Volume</p>
        <div class="summary-stat__value">${formatNumber(stats.packets)}</div>
        <p class="summary-stat__copy">${formatBytes(stats.bytes)} across ${formatNumber(stats.flows)} flows</p>
      </article>
    </div>
    <div class="col-12 col-md-6 col-xl-3">
      <article class="summary-stat h-100">
        <p class="summary-stat__label">Host Scope</p>
        <div class="summary-stat__value">${formatNumber(stats.unique_hosts)}</div>
        <p class="summary-stat__copy">${stats.internal_hosts} internal | ${stats.external_hosts} external</p>
      </article>
    </div>
    <div class="col-12 col-md-6 col-xl-3">
      <article class="summary-stat h-100">
        <p class="summary-stat__label">Artifact Recovery</p>
        <div class="summary-stat__value">${formatNumber(artifactSummary.count)}</div>
        <p class="summary-stat__copy">${artifactSummary.suspicious_count} suspicious | ${artifactSummary.delivered_hosts} delivered hosts</p>
      </article>
    </div>
    <div class="col-12 col-md-6 col-xl-3">
      <article class="summary-stat h-100">
        <p class="summary-stat__label">Local Threat Intel</p>
        <div class="summary-stat__value">${formatNumber(report.threat_intel_matches.length)}</div>
        <p class="summary-stat__copy">${artifactSummary.intel_match_count} recovered-file matches from the local bundle</p>
      </article>
    </div>
  `;
}

function renderAnalystSummary(analystSummary) {
  const findings = renderStackItems(analystSummary.finding_summary, "No notable findings were summarized.");
  const evidence = renderStackItems(analystSummary.evidence, "No extra evidence strings were generated.");
  const hypotheses = renderStackItems(analystSummary.attack_hypotheses, "No attack hypotheses were inferred.");
  const actions = renderStackItems(analystSummary.recommended_actions, "No follow-up actions were proposed.");

  elements.analystSummary.innerHTML = `
    <div class="briefing-board">
      <article class="briefing-lead">
        <p class="briefing-lead__eyebrow">Narrative</p>
        <p class="briefing-lead__copy">${escapeHtml(analystSummary.overview)}</p>
        <div class="finding__details">
          <span>${escapeHtml(analystSummary.engine)}</span>
          <span>${escapeHtml(analystSummary.confidence)} confidence</span>
        </div>
      </article>
      <div class="briefing-grid">
        <article class="briefing-card">
          <p class="briefing-card__title">Finding Summary</p>
          <div class="stack-list">${findings}</div>
        </article>
        <article class="briefing-card">
          <p class="briefing-card__title">Evidence</p>
          <div class="stack-list">${evidence}</div>
        </article>
        <article class="briefing-card">
          <p class="briefing-card__title">Attack Hypotheses</p>
          <div class="stack-list">${hypotheses}</div>
        </article>
        <article class="briefing-card">
          <p class="briefing-card__title">Recommended Actions</p>
          <div class="stack-list">${actions}</div>
        </article>
      </div>
    </div>
  `;
}

function renderDirectoryServices(directoryServices) {
  const servers = directoryServices.likely_directory_servers;
  const serverMarkup = servers.length
    ? servers
        .map(
          (server) => `
            <div class="stack-list__item">
              <strong><code>${escapeHtml(server.ip)}</code></strong><br />
              ports: ${escapeHtml(server.ports.join(", "))} | clients: ${server.client_count}
            </div>
          `
        )
        .join("")
    : `<div class="stack-list__item">No directory-centric server candidates were inferred.</div>`;

  const protocolChips = [
    ["Kerberos", directoryServices.kerberos_activity.count],
    ["LDAP", directoryServices.ldap_activity.count],
    ["SMB", directoryServices.smb_activity.count],
    ["RPC", directoryServices.rpc_activity.count],
  ]
    .map(([label, count]) => `<span class="mini-chip">${escapeHtml(label)} ${count}</span>`)
    .join("");

  elements.directoryServices.innerHTML = `
    <div class="analyst-copy">
      <div class="analyst-section">
        <h4>Likely Directory Servers</h4>
        <div class="stack-list">${serverMarkup}</div>
      </div>
      <div class="analyst-section">
        <h4>Protocol Totals</h4>
        <div class="finding__details">${protocolChips}</div>
      </div>
      <div class="analyst-section">
        <h4>Key Signals</h4>
        <div class="stack-list">
          <div class="stack-list__item">Kerberos messages: ${formatCounter(directoryServices.kerberos_activity.message_types)}</div>
          <div class="stack-list__item">LDAP operations: ${formatCounter(directoryServices.ldap_activity.operations)}</div>
          <div class="stack-list__item">RPC packets: ${formatCounter(directoryServices.rpc_activity.packet_types)}</div>
          <div class="stack-list__item">DRSUAPI packets: ${directoryServices.rpc_activity.drsuapi_packets}</div>
        </div>
      </div>
    </div>
  `;
}

function renderDetections(detections) {
  const buckets = {
    all: detections.length,
    high: detections.filter((item) => item.severity === "high").length,
    medium: detections.filter((item) => item.severity === "medium").length,
    low: detections.filter((item) => item.severity === "low").length,
  };
  const currentFilter = buckets[state.findingFilter] !== undefined ? state.findingFilter : "all";
  const visibleDetections =
    currentFilter === "all" ? detections : detections.filter((item) => item.severity === currentFilter);

  const tabs = [
    ["all", "All", buckets.all],
    ["high", "High", buckets.high],
    ["medium", "Medium", buckets.medium],
    ["low", "Low", buckets.low],
  ]
    .map(
      ([value, label, count]) => `
        <button class="tab-button ${currentFilter === value ? "is-active" : ""}" data-finding-filter="${value}" type="button">
          ${escapeHtml(label)} <span>${count}</span>
        </button>
      `
    )
    .join("");

  const body = visibleDetections.length
    ? visibleDetections
        .map((detection) => {
          const detailEntries = Object.entries(detection.details || {})
            .filter(([, value]) => value !== null && value !== "" && String(value) !== "[]")
            .slice(0, 6)
            .map(([key, value]) => `<span>${escapeHtml(key)}: ${escapeHtml(stringifyValue(value))}</span>`)
            .join("");
          return `
            <article class="finding finding--${normalizeSeverityClass(detection.severity)}">
              <div class="severity-tag severity-tag--${normalizeSeverityClass(detection.severity)}">${escapeHtml(detection.severity)}</div>
              <p class="finding__summary">${escapeHtml(detection.summary)}</p>
              <div class="finding__details">${detailEntries}</div>
            </article>
          `;
        })
        .join("")
    : `<div class="empty-state">No findings in the ${escapeHtml(currentFilter)} bucket.</div>`;

  elements.detections.innerHTML = `
    <div class="tab-strip">${tabs}</div>
    <div class="finding-stack">${body}</div>
  `;
  elements.detections.querySelectorAll("[data-finding-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.findingFilter = button.getAttribute("data-finding-filter") || "all";
      renderDetections(detections);
    });
  });
}

function renderSuspiciousHosts(hosts) {
  if (!hosts.length) {
    elements.suspiciousHosts.innerHTML = `<div class="empty-state">No host scored above the current evidence threshold.</div>`;
    return;
  }
  elements.suspiciousHosts.innerHTML = `
    <div class="host-risk-list">
      ${hosts
        .map(
          (host) => `
            <article class="evidence-card">
              <div class="flow-row__top">
                <div>
                  <strong><code>${escapeHtml(host.ip)}</code></strong>
                  <div class="finding__details finding__details--tight">
                    <span class="role-badge role-badge--${escapeHtml(host.role)}">${escapeHtml(host.role)}</span>
                    <span class="severity-tag severity-tag--${normalizeSeverityClass(host.status)}">${escapeHtml(host.status)}</span>
                    <span>score ${host.score}</span>
                  </div>
                </div>
              </div>
              <div class="stack-list">
                ${host.evidence
                  .map((item) => `<div class="stack-list__item">${escapeHtml(item)}</div>`)
                  .join("")}
              </div>
              <div class="link-row">
                ${buildPivotLink("AbuseIPDB", `https://www.abuseipdb.com/check/${host.ip}`)}
                ${buildPivotLink("Shodan", `https://www.shodan.io/host/${host.ip}`)}
                ${buildPivotLink("Censys", `https://search.censys.io/hosts/${host.ip}`)}
              </div>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderArtifacts(artifacts, artifactSummary) {
  if (!artifacts.length) {
    elements.artifacts.innerHTML = `<div class="empty-state">No recoverable HTTP artifacts were reconstructed.</div>`;
    return;
  }
  elements.artifacts.innerHTML = `
    <div class="finding__details">
      <span>${artifactSummary.count} recovered</span>
      <span>${artifactSummary.suspicious_count} suspicious</span>
      <span>${artifactSummary.intel_match_count} intel matches</span>
    </div>
    <div class="artifact-list">
      ${artifacts
        .map(
          (artifact) => `
            <article class="artifact-card">
              <div class="flow-row__top">
                <strong>${escapeHtml(artifact.filename)}</strong>
                <span>${formatBytes(artifact.size)}</span>
              </div>
              <div class="finding__details finding__details--tight">
                <span>${escapeHtml(artifact.type)}</span>
                <span>${artifact.suspicious ? "suspicious" : "recovered"}</span>
                <span>${artifact.complete ? "complete body" : "partial body"}</span>
                <span>${artifact.intel_matches.length} intel matches</span>
              </div>
              <div class="artifact-card__meta">
                <span><code>${escapeHtml(artifact.source_ip)}</code> -> <code>${escapeHtml(artifact.destination_ip)}</code></span>
                <span>${escapeHtml((artifact.request_host || artifact.source_ip) + (artifact.request_path || ""))}</span>
                <span class="hash-inline">${escapeHtml(artifact.sha256)}</span>
              </div>
              <div class="link-row">
                ${buildPivotLink("VirusTotal", `https://www.virustotal.com/gui/file/${artifact.sha256}`)}
                ${buildPivotLink("AlienVault OTX", `https://otx.alienvault.com/indicator/file/${artifact.sha256}`)}
                ${
                  artifact.request_host
                    ? buildPivotLink("VT Domain", `https://www.virustotal.com/gui/domain/${artifact.request_host}`)
                    : ""
                }
              </div>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderThreatIntel(matches) {
  if (!matches.length) {
    elements.threatIntel.innerHTML = `<div class="empty-state">No local threat-intelligence matches were found for the recovered indicators.</div>`;
    return;
  }
  elements.threatIntel.innerHTML = `
    <div class="intel-grid">
      ${matches
        .map(
          (match) => `
            <article class="intel-card">
              <div class="flow-row__top">
                <strong>${escapeHtml(match.name || "Local intel match")}</strong>
                <span class="severity-tag severity-tag--${normalizeSeverityClass(match.severity || "medium")}">${escapeHtml(
                  match.severity || "medium"
                )}</span>
              </div>
              <p class="intel-card__copy">${escapeHtml(match.notes || "Matched against the local indicator bundle.")}</p>
              <div class="finding__details finding__details--tight">
                <span>${escapeHtml(match.family || "unknown family")}</span>
                <span>${escapeHtml(match.match_type || "match")}</span>
                ${match.filename ? `<span>${escapeHtml(match.filename)}</span>` : ""}
                ${match.domain ? `<span>${escapeHtml(match.domain)}</span>` : ""}
              </div>
              ${
                match.artifact_sha256
                  ? `<div class="artifact-card__meta"><span class="hash-inline">${escapeHtml(match.artifact_sha256)}</span></div>`
                  : ""
              }
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderProtocols(appProtocols, layer4Protocols) {
  const appRows = buildMetricRows(appProtocols);
  elements.protocols.innerHTML = `
    <div class="metric-list">
      ${appRows || `<div class="empty-state">No application protocols were extracted.</div>`}
    </div>
    <div class="finding__details" style="margin-top: 1rem;">
      ${Object.entries(layer4Protocols)
        .map(([name, count]) => `<span class="mini-chip">${escapeHtml(name)} | ${count}</span>`)
        .join("")}
    </div>
  `;
}

function renderPorts(portRows) {
  if (!portRows.length) {
    elements.ports.innerHTML = `<div class="empty-state">No transport ports were tracked.</div>`;
    return;
  }
  const maxPackets = Math.max(...portRows.map((row) => row.packets), 1);
  elements.ports.innerHTML = `
    <div class="metric-list">
      ${portRows
        .map(
          (row) => `
            <div class="metric-list__row">
              <div>
                <div class="flow-row__top">
                  <strong>Port ${row.port}</strong>
                  <span>${row.packets} packets</span>
                </div>
                <div class="metric-bar"><span style="width:${(row.packets / maxPackets) * 100}%"></span></div>
              </div>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function renderHosts(hosts) {
  if (!hosts.length) {
    elements.hosts.innerHTML = `<div class="empty-state">No host inventory is available.</div>`;
    return;
  }
  elements.hosts.innerHTML = `
    <table class="host-table">
      <thead>
        <tr>
          <th>Host</th>
          <th>Role</th>
          <th>Total Bytes</th>
          <th>Total Packets</th>
          <th>Peers</th>
        </tr>
      </thead>
      <tbody>
        ${hosts
          .map(
            (host) => `
              <tr>
                <td><code>${escapeHtml(host.ip)}</code></td>
                <td><span class="role-badge role-badge--${escapeHtml(host.role)}">${escapeHtml(host.role)}</span></td>
                <td>${formatBytes(host.total_bytes)}</td>
                <td>${formatNumber(host.total_packets)}</td>
                <td>${formatNumber(host.peer_count)}</td>
              </tr>
            `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function renderFlows(flows) {
  if (!flows.length) {
    elements.flows.innerHTML = `<div class="empty-state">No flows were reconstructed.</div>`;
    return;
  }
  const maxBytes = Math.max(...flows.map((flow) => flow.bytes), 1);
  elements.flows.innerHTML = `
    <div class="flow-list">
      ${flows
        .map(
          (flow) => `
            <div class="flow-row">
              <div class="flow-row__top">
                <strong>${escapeHtml(shorten(flow.flow, 64))}</strong>
                <span>${formatBytes(flow.bytes)} | ${flow.packets} packets</span>
              </div>
              <div class="flow-bar"><span style="width:${(flow.bytes / maxBytes) * 100}%"></span></div>
              <div class="finding__details">
                <span>${formatDuration(flow.duration_seconds)}</span>
                <span>${escapeHtml(stringifyProtocols(flow.app_protocols))}</span>
              </div>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function renderTimeline(events, captureStartedAt) {
  if (!events.length) {
    elements.timeline.innerHTML = `<div class="empty-state">No timeline events were generated.</div>`;
    return;
  }
  elements.timeline.innerHTML = `
    <div class="timeline-list">
      ${events
        .map(
          (event) => `
            <article class="timeline-row">
              <div class="timeline-row__time">
                <strong>${escapeHtml(formatMoment(event.timestamp))}</strong>
                <span>${escapeHtml(formatTimelineDelta(event.timestamp, captureStartedAt))}</span>
              </div>
              <div class="timeline-row__body">
                <div class="flow-row__top">
                  <strong>${escapeHtml(event.summary)}</strong>
                  <span class="severity-tag severity-tag--${normalizeSeverityClass(event.severity)}">${escapeHtml(event.severity)}</span>
                </div>
                <div class="finding__details finding__details--tight">
                  <span>${escapeHtml(event.category)}</span>
                  ${event.host_ip ? `<span><code>${escapeHtml(event.host_ip)}</code></span>` : ""}
                  ${event.peer_ip ? `<span><code>${escapeHtml(event.peer_ip)}</code></span>` : ""}
                  ${event.packet_index ? `<span>frame ${event.packet_index}</span>` : ""}
                </div>
              </div>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderImportantFrames(frames) {
  if (!frames.length) {
    elements.importantFrames.innerHTML = `<div class="empty-state">No important frames were highlighted.</div>`;
    return;
  }
  elements.importantFrames.innerHTML = `
    <div class="timeline-list">
      ${frames
        .map(
          (frame) => `
            <article class="timeline-row timeline-row--frame">
              <div class="timeline-row__time">
                <strong>#${frame.packet_index}</strong>
                <span>${escapeHtml(formatMoment(frame.timestamp))}</span>
              </div>
              <div class="timeline-row__body">
                <div class="flow-row__top">
                  <strong>${escapeHtml(frame.summary)}</strong>
                  <span class="severity-tag severity-tag--${normalizeSeverityClass(frame.severity)}">${escapeHtml(frame.severity)}</span>
                </div>
                <div class="finding__details finding__details--tight">
                  <span>${escapeHtml(frame.protocol || "packet")}</span>
                  ${frame.src_ip ? `<span><code>${escapeHtml(frame.src_ip)}</code></span>` : ""}
                  ${frame.dst_ip ? `<span><code>${escapeHtml(frame.dst_ip)}</code></span>` : ""}
                  ${
                    frame.packet_meta && frame.packet_meta.sha256
                      ? `<span>${escapeHtml(shortHash(frame.packet_meta.sha256, 18))}</span>`
                      : ""
                  }
                </div>
              </div>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderRecordList(target, records, formatter) {
  if (!records.length) {
    target.innerHTML = `<div class="empty-state">No data in this section.</div>`;
    return;
  }
  target.innerHTML = `<div class="kv-list">${records.map(formatter).join("")}</div>`;
}

function renderRpcSection(rpcEvents, smbEvents) {
  const rows = [];
  rpcEvents.slice(0, 8).forEach((event) => {
    rows.push(
      buildRecordEntry(
        event.packet_type || "RPC",
        buildEndpointMeta(event.client_ip, event.server_ip, [
          buildMetaChip("DRSUAPI", event.contains_drsuapi ? "yes" : "no"),
        ])
      )
    );
  });
  smbEvents.slice(0, 4).forEach((event) => {
    rows.push(
      buildRecordEntry(
        `${event.version || "SMB"} ${event.command || "traffic"}`,
        buildEndpointMeta(event.client_ip, event.server_ip)
      )
    );
  });
  elements.rpc.innerHTML = rows.length ? `<div class="kv-list">${rows.join("")}</div>` : `<div class="empty-state">No RPC or SMB metadata was extracted.</div>`;
}

function renderWarnings(warnings) {
  if (!warnings.length) {
    elements.warnings.innerHTML = `<div class="empty-state">No parser warnings.</div>`;
    return;
  }
  elements.warnings.innerHTML = `
    <div class="kv-list">
      ${warnings.map((warning) => `<div class="empty-state">${escapeHtml(warning)}</div>`).join("")}
    </div>
  `;
}

function buildMetricRows(metrics) {
  const entries = Object.entries(metrics || {});
  if (!entries.length) {
    return "";
  }
  const maxValue = Math.max(...entries.map(([, value]) => value), 1);
  return entries
    .sort((a, b) => b[1] - a[1])
    .map(
      ([name, value]) => `
        <div class="metric-list__row">
          <div class="flow-row__top">
            <strong>${escapeHtml(name)}</strong>
            <span>${value}</span>
          </div>
          <div class="metric-bar"><span style="width:${(value / maxValue) * 100}%"></span></div>
        </div>
      `
    )
    .join("");
}

function renderStackItems(items, emptyCopy) {
  if (!items || !items.length) {
    return `<div class="stack-list__item">${escapeHtml(emptyCopy)}</div>`;
  }
  return items.map((item) => `<div class="stack-list__item">${escapeHtml(item)}</div>`).join("");
}

function buildPivotLink(label, url) {
  return `<a class="pivot-link" href="${escapeHtml(url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(label)}</a>`;
}

function buildMetaChip(label, value) {
  return `<span class="endpoint-chip">${escapeHtml(label)} ${escapeHtml(value)}</span>`;
}

function buildEndpointMeta(src, dst, extras = []) {
  return `
    <div class="kv-list__meta">
      <span class="endpoint-chip">${escapeHtml(src || "unknown")}</span>
      <span class="endpoint-arrow">to</span>
      <span class="endpoint-chip">${escapeHtml(dst || "unknown")}</span>
      ${extras.join("")}
    </div>
  `;
}

function buildRecordEntry(title, metaMarkup = "", noteMarkup = "") {
  return `
    <article class="kv-list__entry">
      <strong class="kv-list__title">${escapeHtml(title)}</strong>
      ${metaMarkup}
      ${noteMarkup}
    </article>
  `;
}

function formatDnsEntry(entry) {
  return buildRecordEntry(entry.query, buildEndpointMeta(entry.src_ip, entry.dst_ip));
}

function formatHttpEntry(entry) {
  const label =
    entry.kind === "request"
      ? `${entry.method} ${entry.host || entry.dst_ip}${entry.path || ""}`
      : `HTTP ${entry.status_code || "?"} ${entry.reason || ""}`;
  const note = entry.path ? `<div class="kv-list__note">${escapeHtml(entry.path)}</div>` : "";
  return buildRecordEntry(label, buildEndpointMeta(entry.src_ip, entry.dst_ip), note);
}

function formatTlsEntry(entry) {
  return buildRecordEntry(
    entry.server_name || "ClientHello without SNI",
    buildEndpointMeta(entry.src_ip, entry.dst_ip)
  );
}

function formatKerberosEntry(entry) {
  const tokens = (entry.token_sample || []).join(", ") || "no token sample";
  return buildRecordEntry(
    entry.message_name || "Kerberos",
    buildEndpointMeta(entry.client_ip, entry.server_ip),
    `<div class="kv-list__note">${escapeHtml(tokens)}</div>`
  );
}

function formatLdapEntry(entry) {
  const keywords = (entry.keywords || []).join(", ") || "no keywords";
  return buildRecordEntry(
    entry.operation || "LDAP",
    buildEndpointMeta(entry.client_ip, entry.server_ip),
    `<div class="kv-list__note">${escapeHtml(keywords)}</div>`
  );
}

function downloadJsonReport() {
  if (!state.currentReport) {
    return;
  }
  downloadBlob(
    `${slugify(state.currentReport.metadata.source_name || "wireglass-report")}.json`,
    "application/json",
    JSON.stringify(state.currentReport, null, 2)
  );
}

function downloadHtmlReport() {
  if (!state.currentReport) {
    return;
  }
  downloadBlob(
    `${slugify(state.currentReport.metadata.source_name || "wireglass-report")}.html`,
    "text/html;charset=utf-8",
    buildStandaloneReportHtml(state.currentReport)
  );
}

function downloadBlob(filename, mimeType, content) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildStandaloneReportHtml(report) {
  const analystSummary = report.analyst_summary;
  const detections = report.detections.length
    ? report.detections
        .map(
          (detection) => `
            <article class="finding finding--${normalizeSeverityClass(detection.severity)}">
              <div class="severity">${escapeHtml(detection.severity)}</div>
              <h3>${escapeHtml(detection.summary)}</h3>
              <p>${escapeHtml(
                Object.entries(detection.details || {})
                  .filter(([, value]) => value !== null && value !== "")
                  .slice(0, 6)
                  .map(([key, value]) => `${key}: ${stringifyValue(value)}`)
                  .join(" | ")
              )}</p>
            </article>
          `
        )
        .join("")
    : `<p class="quiet">No detections fired.</p>`;

  const artifacts = report.artifacts.length
    ? report.artifacts
        .map(
          (artifact) => `
            <article class="card compact">
              <h3>${escapeHtml(artifact.filename)}</h3>
              <p>${escapeHtml(artifact.type)} | ${formatBytes(artifact.size)} | ${artifact.intel_matches.length} intel matches</p>
              <p class="quiet">${escapeHtml(artifact.source_ip)} -> ${escapeHtml(artifact.destination_ip)}</p>
              <p class="hash">${escapeHtml(artifact.sha256)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="quiet">No artifacts were recovered.</p>`;

  const intel = report.threat_intel_matches.length
    ? report.threat_intel_matches
        .map(
          (match) => `
            <article class="card compact">
              <h3>${escapeHtml(match.name || "Local intel match")}</h3>
              <p>${escapeHtml(match.family || "unknown family")} | ${escapeHtml(match.match_type || "match")}</p>
              <p class="quiet">${escapeHtml(match.filename || match.domain || "indicator")}</p>
            </article>
          `
        )
        .join("")
    : `<p class="quiet">No local intel matches.</p>`;

  const suspiciousHosts = report.suspicious_hosts.length
    ? report.suspicious_hosts
        .map(
          (host) => `
            <tr>
              <td>${escapeHtml(host.ip)}</td>
              <td>${escapeHtml(host.role)}</td>
              <td>${host.score}</td>
              <td>${escapeHtml(host.status)}</td>
              <td>${escapeHtml((host.evidence || []).slice(0, 2).join(" | "))}</td>
            </tr>
          `
        )
        .join("")
    : `<tr><td colspan="5">No suspicious hosts were scored.</td></tr>`;

  const pivots = ((report.investigation_shortcuts || {}).priority || []).length
    ? report.investigation_shortcuts.priority
        .map(
          (item) => `
            <article class="card compact">
              <h3>${escapeHtml(item.title || item.indicator || "indicator")}</h3>
              <p>${escapeHtml(item.reason || "Recommended next pivot.")}</p>
              <p class="quiet">${escapeHtml(item.kind || "indicator")} | ${escapeHtml(item.severity || "low")}</p>
              <p class="quiet">${(item.links || []).map((link) => `<a href="${escapeHtml(link.url)}">${escapeHtml(link.label)}</a>`).join(" | ")}</p>
            </article>
          `
        )
        .join("")
    : `<p class="quiet">No shortcut pivots were generated.</p>`;

  const timeline = report.timeline.length
    ? report.timeline
        .slice(0, 16)
        .map(
          (event) => `
            <div class="timeline-row">
              <div class="time">${escapeHtml(formatMoment(event.timestamp))}</div>
              <div>
                <strong>${escapeHtml(event.summary)}</strong>
                <div class="quiet">${escapeHtml(event.category)} | ${escapeHtml(event.host_ip || "-")}${
                  event.packet_index ? ` | frame ${event.packet_index}` : ""
                }</div>
              </div>
            </div>
          `
        )
        .join("")
    : `<p class="quiet">No timeline events were generated.</p>`;

  const talkers = report.top_talkers
    .map(
      (host) => `
        <tr>
          <td>${escapeHtml(host.ip)}</td>
          <td>${escapeHtml(host.role)}</td>
          <td>${formatBytes(host.total_bytes)}</td>
          <td>${formatNumber(host.total_packets)}</td>
        </tr>
      `
    )
    .join("");

  return `<!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${escapeHtml(report.metadata.source_name)} - Wireglass Report</title>
      <style>
        :root {
          --bg: #f5efe6;
          --ink: #16212b;
          --muted: #5f6b75;
          --panel: rgba(255,255,255,.82);
          --line: rgba(22,33,43,.08);
          --teal: #1d8c78;
          --amber: #ebaa4b;
          --coral: #df6b45;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          padding: 2rem;
          color: var(--ink);
          font-family: Bahnschrift, "Segoe UI Variable", "Trebuchet MS", sans-serif;
          background:
            radial-gradient(circle at top left, rgba(235,170,75,.16), transparent 26%),
            radial-gradient(circle at right 14%, rgba(29,140,120,.16), transparent 22%),
            linear-gradient(180deg, #f8f3ec 0%, #f0e8dd 100%);
        }
        .shell { max-width: 1120px; margin: 0 auto; }
        .hero, .card, .finding {
          background: var(--panel);
          border: 1px solid var(--line);
          border-radius: 24px;
          box-shadow: 0 18px 44px rgba(20,30,42,.1);
        }
        .hero { padding: 1.6rem; margin-bottom: 1rem; }
        .hero p { color: var(--muted); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1rem; }
        .card { padding: 1.1rem; }
        .card h2, .card h3 { margin-top: 0; }
        .card.compact { padding: .95rem 1rem; }
        .section { margin-bottom: 1rem; }
        .finding { padding: 1rem; margin-bottom: .8rem; }
        .finding--high { border-left: 6px solid var(--coral); }
        .finding--medium { border-left: 6px solid var(--amber); }
        .finding--low, .finding--quiet { border-left: 6px solid var(--teal); }
        .severity {
          display: inline-block;
          margin-bottom: .65rem;
          padding: .3rem .55rem;
          border-radius: 999px;
          background: rgba(22,33,43,.08);
          font-size: .75rem;
          text-transform: uppercase;
          letter-spacing: .12em;
        }
        .hash {
          margin: .4rem 0 0;
          padding: .7rem;
          border-radius: 14px;
          background: rgba(22,33,43,.06);
          font-family: "Cascadia Code", Consolas, monospace;
          font-size: .86rem;
          word-break: break-all;
        }
        .quiet { color: var(--muted); }
        table { width: 100%; border-collapse: collapse; }
        th, td {
          padding: .7rem .5rem;
          border-bottom: 1px solid var(--line);
          text-align: left;
          vertical-align: top;
        }
        th {
          text-transform: uppercase;
          letter-spacing: .12em;
          font-size: .74rem;
          color: var(--muted);
        }
        .timeline-row {
          display: grid;
          grid-template-columns: 180px 1fr;
          gap: 1rem;
          padding: .8rem 0;
          border-bottom: 1px solid var(--line);
        }
        .timeline-row:last-child { border-bottom: 0; }
        .time { color: var(--muted); font-size: .9rem; }
        @media (max-width: 820px) {
          body { padding: 1rem; }
          .timeline-row { grid-template-columns: 1fr; gap: .35rem; }
        }
      </style>
    </head>
    <body>
      <div class="shell">
        <section class="hero">
          <p>Wireglass offline report</p>
          <h1>${escapeHtml(report.summary.headline)}</h1>
          <p>Source: ${escapeHtml(report.metadata.source_name)} | Format: ${escapeHtml(
            report.metadata.capture_format
          )} | Risk: ${report.summary.risk_score} | Capture SHA-256: ${escapeHtml(shortHash(report.metadata.capture_sha256, 28))}</p>
          <p>${buildPivotLink("VirusTotal", `https://www.virustotal.com/gui/file/${report.metadata.capture_sha256}`)} ${buildPivotLink(
            "AlienVault OTX",
            `https://otx.alienvault.com/indicator/file/${report.metadata.capture_sha256}`
          )}</p>
        </section>

        <section class="grid section">
          <article class="card"><h2>Packets</h2><p>${formatNumber(report.stats.packets)}</p></article>
          <article class="card"><h2>Flows</h2><p>${formatNumber(report.stats.flows)}</p></article>
          <article class="card"><h2>Hosts</h2><p>${formatNumber(report.stats.unique_hosts)}</p></article>
          <article class="card"><h2>Artifacts</h2><p>${formatNumber(report.artifact_summary.count)}</p></article>
        </section>

        <section class="card section">
          <h2>Analyst Summary</h2>
          <p>${escapeHtml(analystSummary.overview)}</p>
          <p><strong>Evidence:</strong> ${escapeHtml((analystSummary.evidence || []).join(" | "))}</p>
          <p><strong>Hypotheses:</strong> ${escapeHtml((analystSummary.attack_hypotheses || []).join(" | "))}</p>
          <p><strong>Actions:</strong> ${escapeHtml((analystSummary.recommended_actions || []).join(" | "))}</p>
        </section>

        <section class="card section">
          <h2>Findings</h2>
          ${detections}
        </section>

        <section class="card section">
          <h2>Priority Pivots</h2>
          ${pivots}
        </section>

        <section class="grid section">
          <article class="card">
            <h2>Recovered Artifacts</h2>
            ${artifacts}
          </article>
          <article class="card">
            <h2>Threat Intel</h2>
            ${intel}
          </article>
        </section>

        <section class="card section">
          <h2>Potentially Impacted Hosts</h2>
          <table>
            <thead><tr><th>Host</th><th>Role</th><th>Score</th><th>Status</th><th>Evidence</th></tr></thead>
            <tbody>${suspiciousHosts}</tbody>
          </table>
        </section>

        <section class="card section">
          <h2>Timeline</h2>
          ${timeline}
        </section>

        <section class="card section">
          <h2>Top Talkers</h2>
          <table>
            <thead><tr><th>Host</th><th>Role</th><th>Bytes</th><th>Packets</th></tr></thead>
            <tbody>${talkers}</tbody>
          </table>
        </section>
      </div>
    </body>
  </html>`;
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = units[0];
  for (const nextUnit of units) {
    unit = nextUnit;
    if (size < 1024 || nextUnit === units[units.length - 1]) {
      break;
    }
    size /= 1024;
  }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${unit}`;
}

function formatDuration(seconds) {
  const value = Number(seconds || 0);
  if (value < 1) {
    return `${Math.round(value * 1000)} ms`;
  }
  if (value < 60) {
    return `${value.toFixed(1)} s`;
  }
  return `${(value / 60).toFixed(1)} min`;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatMoment(seconds) {
  const value = Number(seconds || 0);
  if (!value) {
    return "capture";
  }
  if (value > 1_000_000_000) {
    return new Date(value * 1000).toLocaleString();
  }
  return `${value.toFixed(3)} s`;
}

function formatTimelineDelta(timestamp, captureStartedAt) {
  const value = Number(timestamp || 0);
  if (!value || !captureStartedAt) {
    return "capture-relative unavailable";
  }
  const startMs = Date.parse(captureStartedAt);
  if (!Number.isFinite(startMs)) {
    return "capture-relative unavailable";
  }
  const deltaSeconds = (value * 1000 - startMs) / 1000;
  return `${deltaSeconds >= 0 ? "+" : ""}${deltaSeconds.toFixed(2)} s`;
}

function normalizeSeverityClass(value) {
  const severity = String(value || "quiet").toLowerCase();
  if (severity === "high" || severity === "medium" || severity === "low") {
    return severity;
  }
  return "quiet";
}

function shortHash(value, maxLength = 14) {
  const text = String(value || "");
  if (!text) {
    return "";
  }
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}

function shorten(value, maxLength) {
  const text = String(value || "");
  return text.length > maxLength ? `${text.slice(0, maxLength - 3)}...` : text;
}

function stringifyProtocols(protocols) {
  const entries = Object.entries(protocols || {});
  return entries.length ? entries.map(([name, count]) => `${name} ${count}`).join(" | ") : "No app protocol";
}

function stringifyValue(value) {
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value === "object" && value !== null) {
    return JSON.stringify(value);
  }
  return String(value);
}

function formatCounter(counter) {
  const entries = Object.entries(counter || {});
  return entries.length ? entries.map(([name, count]) => `${name} ${count}`).join(" | ") : "none";
}

function slugify(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || "wireglass-report";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

initialize();
