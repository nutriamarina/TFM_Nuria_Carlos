import { useState, useEffect, useRef } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";

const C = {
  bg: "#060d1b", surface: "#0c1628", card: "#0f1e30",
  border: "#1a2d45", borderBright: "#2a4060",
  accent: "#00c8ff", accentDim: "#0088aa",
  danger: "#ff3b3b", warning: "#ffb800", success: "#00d878",
  text: "#c8dce8", textMuted: "#5a7a8a",
  pill: { malicious: "#ff3b3b22", suspicious: "#ffb80022", clean: "#00d87822", unknown: "#00c8ff22" },
  pillText: { malicious: "#ff6060", suspicious: "#ffcc44", clean: "#00d878", unknown: "#00c8ff" },
};

const normalizeScore = (s) => {
  if (!s && s !== 0) return 0;
  if (s <= 10) return Math.round(s * 10);
  return Math.round(s);
};

const deriveVerdict = (score) => {
  const s = normalizeScore(score);
  if (s >= 70) return "malicious";
  if (s >= 30) return "suspicious";
  if (s > 0) return "suspicious";
  return "clean";
};

const normalizeTask = (t) => ({
  id: t.id,
  name: (() => { const raw = t.target || t.sample?.name || "Unknown"; return raw.split("/").pop().split("\\").pop() || raw; })(),
  type: t.category || "file",
  status: t.status || "unknown",
  verdict: deriveVerdict(t.score),
  score: normalizeScore(t.score),
  family: t.malfamily || null,
  time: (t.started_on || t.added_on || "").replace("T", " ").slice(0, 16),
  sha256: t.sample?.sha256 || null,
  platform: t.platform || "windows",
  tags: Array.isArray(t.tags) ? t.tags.map(tg => typeof tg === "string" ? tg : tg.name).filter(Boolean) : [],
});

// Limita una lista a un máximo de elementos para que el render no se cuelgue
// con análisis que tienen miles de entradas (ransomware cifrando archivos,
// malware con beaconing masivo, etc.), conservando el total real aparte.
// El JSON de CAPE no siempre es consistente entre versiones/tipos de análisis:
// algunos campos que normalmente son listas pueden venir como string, objeto,
// null, o contener elementos null sueltos. asArray() evita que cualquiera de
// esos casos reviente el render entero de la página.
const asArray = (v) => Array.isArray(v) ? v.filter(x => x !== null && x !== undefined) : [];

const fmtSeconds = (s) => s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;

// Limita una lista a un máximo de elementos para que el render no se cuelgue
// con análisis que tienen miles de entradas, conservando el total real aparte.
const capList = (arr, max = 250) => {
  const safe = asArray(arr);
  const out = safe.slice(0, max);
  out.__total = safe.length;
  return out;
};

const normalizeReport = (r, id) => {
  const score = r.malscore ?? r.info?.score ?? 0;
  const net = r.network || {};

  // ── Red: extracción completa por categoría, con tope de render por seguridad ──
  const network = {
    hosts: capList(asArray(net.hosts).map(h => typeof h === "string" ? h : (h?.ip || h?.host || "")).filter(Boolean)),
    domains: capList(asArray(net.domains).map(d => ({ domain: d?.domain || d?.request || "", ip: d?.ip || "" }))),
    dns: capList(asArray(net.dns).map(d => ({
      request: d?.request || "?",
      type: d?.type || "A",
      answers: asArray(d?.answers).slice(0, 10).map(a => a?.data || a).filter(Boolean),
    }))),
    http: capList(asArray(net.http).map(h => ({
      method: h?.method || "GET",
      host: h?.host || h?.dst || "?",
      uri: h?.uri || h?.path || "",
      ua: h?.["user-agent"] || h?.user_agent || "",
    }))),
    tcp: capList(asArray(net.tcp).map(c => ({ src: c?.src || "?", sport: c?.sport, dst: c?.dst || "?", dport: c?.dport }))),
    udp: capList(asArray(net.udp).map(c => ({ src: c?.src || "?", sport: c?.sport, dst: c?.dst || "?", dport: c?.dport }))),
    smtp: capList(asArray(net.smtp).map(s => ({ dst: s?.dst || "?", raw: s?.raw || "" }))),
  };

  // ── Comportamiento: firmas + árbol de procesos + resumen completo ──
  const behaviors = capList(asArray(r.signatures).map(s => ({
    name: s?.name || "", description: s?.description || "", severity: s?.severity || 0,
  })).filter(b => b.description || b.name).sort((a, b) => (b.severity || 0) - (a.severity || 0)), 200);

  const processes = capList(asArray(r.behavior?.processes).map(p => ({
    pid: p?.process_id, ppid: p?.parent_id, name: p?.process_name || "?",
    path: p?.module_path || "", calls: asArray(p?.calls).length,
    firstSeen: p?.first_seen || "",
  })), 150);

  const bs = r.behavior?.summary || {};
  const behaviorSummary = {
    filesWritten: capList(bs.write_files || bs.files),
    filesRead: capList(bs.read_files),
    filesDeleted: capList(bs.delete_files),
    keysWritten: capList(bs.write_keys || bs.keys),
    keysRead: capList(bs.read_keys),
    keysDeleted: capList(bs.delete_keys),
    mutexes: capList(bs.mutexes),
    commands: capList(bs.command_line || bs.executed_commands),
    dllsLoaded: capList(bs.dll_loaded),
  };

  const droppedFiles = capList(asArray(r.dropped).map(f => ({
    name: f?.name || f?.path || "", type: f?.type || "", size: f?.size || 0,
  })).filter(f => f.name), 100);

  const mitre = [];
  asArray(r.signatures).forEach(s => { asArray(s?.ttp).forEach(t => { if (t?.ttp && !mitre.includes(t.ttp)) mitre.push(t.ttp); }); });

  // Enlaces OSINT de pivote sobre el hash — igual que hace CAPE (VirusTotal,
  // MalwareBazaar...), no son resultados de una API, solo enlaces de búsqueda
  const sha256 = r.target?.file?.sha256 || null;
  const osintLinks = sha256 ? [
    { label: "VT", name: "VirusTotal", url: `https://www.virustotal.com/gui/file/${sha256}`, color: "#ff3b3b" },
    { label: "Bazaar", name: "MalwareBazaar", url: `https://bazaar.abuse.ch/sample/${sha256}/`, color: "#00c8ff" },
    { label: "MWDB", name: "MWDB CERT.pl", url: `https://mwdb.cert.pl/file/${sha256}`, color: "#ffb800" },
  ] : [];

  return {
    id, name: r.target?.file?.name || r.info?.id || String(id),
    type: r.info?.category || "file", status: "reported",
    verdict: deriveVerdict(score), score: normalizeScore(score),
    family: r.malfamily || (r.detections && r.detections[0]) || null,
    sha256: r.target?.file?.sha256 || null,
    platform: r.info?.platform || "windows",
    time: (r.info?.started || r.info?.added || "").replace("T", " ").slice(0, 16),
    tags: asArray(r.signatures).slice(0, 3).map(s => s?.name).filter(Boolean),
    network, behaviors, processes, behaviorSummary, files: droppedFiles, mitre, osintLinks,
  };
};

function Spinner() {
  return <span style={{ display: "inline-block", width: 14, height: 14, border: `2px solid ${C.accent}`, borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />;
}

function VerdictBadge({ v }) {
  return <span style={{ background: C.pill[v] || C.pill.unknown, color: C.pillText[v] || C.pillText.unknown, padding: "2px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>{v}</span>;
}

function ScoreMeter({ score }) {
  const color = score >= 70 ? C.danger : score >= 30 ? C.warning : C.success;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ width: 80, height: 6, background: C.border, borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: score + "%", height: "100%", background: color, borderRadius: 3 }} />
      </div>
      <span style={{ color, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{score}</span>
    </div>
  );
}

function StatCard({ label, value, sub, color }) {
  return (
    <div style={{ background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, padding: "18px 20px", flex: 1 }}>
      <div style={{ fontSize: 12, color: C.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || C.text, fontFamily: "monospace" }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: C.textMuted, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function Sidebar({ view, setView }) {
  const items = [
    { id: "dashboard", icon: "⬡", label: "Dashboard" },
    { id: "submit", icon: "⊕", label: "Analizar" },
    { id: "analyses", icon: "≡", label: "Análisis" },
    { id: "admin", icon: "⚙", label: "Configuración" },
  ];
  return (
    <div style={{ width: 220, background: C.surface, borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", minHeight: "100vh", flexShrink: 0 }}>
      <div style={{ padding: "24px 20px 16px", borderBottom: `1px solid ${C.border}` }}>
        <div style={{ fontSize: 11, color: C.accent, letterSpacing: 3, textTransform: "uppercase", marginBottom: 4 }}>TFM Project</div>
        <div style={{ fontSize: 20, fontWeight: 800, color: C.text }}><span style={{ color: C.accent }}>CAPE</span> Sandbox</div>
        <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2 }}>AI-Enhanced Analysis</div>
      </div>
      <nav style={{ padding: "16px 12px", flex: 1 }}>
        {items.map(item => (
          <button key={item.id} onClick={() => setView(item.id)} style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", marginBottom: 4, background: view === item.id ? "#00c8ff15" : "transparent", border: view === item.id ? "1px solid #00c8ff40" : "1px solid transparent", borderRadius: 6, color: view === item.id ? C.accent : C.textMuted, cursor: "pointer", fontSize: 14, textAlign: "left" }}>
            <span style={{ fontSize: 16 }}>{item.icon}</span>{item.label}
          </button>
        ))}
      </nav>
      <div style={{ padding: "12px 20px", borderTop: `1px solid ${C.border}`, fontSize: 10, color: C.textMuted }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.success }} />
          CAPE · localhost:8000
        </div>
      </div>
    </div>
  );
}

function DashboardView({ setView, setSelectedTask, tasks, loading }) {
  const total = tasks.length;
  const malicious = tasks.filter(t => t.verdict === "malicious").length;
  const suspicious = tasks.filter(t => t.verdict === "suspicious").length;
  const clean = tasks.filter(t => t.verdict === "clean").length;
  const pieData = [
    { name: "Malicious", value: malicious, color: C.danger },
    { name: "Suspicious", value: suspicious, color: C.warning },
    { name: "Clean", value: clean, color: C.success },
  ];
  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Dashboard</h1>
        <p style={{ color: C.textMuted, fontSize: 13, margin: "4px 0 0" }}>Resumen de actividad de análisis</p>
      </div>
      {loading ? (
        <div style={{ display: "flex", alignItems: "center", gap: 10, color: C.textMuted, padding: 40 }}><Spinner /> Cargando datos de CAPE...</div>
      ) : (
        <>
          <div style={{ display: "flex", gap: 16, marginBottom: 24 }}>
            <StatCard label="Total análisis" value={total} sub="Todos los análisis" />
            <StatCard label="Maliciosos" value={malicious} color={C.danger} sub={total ? `${Math.round(malicious / total * 100)}% del total` : ""} />
            <StatCard label="Sospechosos" value={suspicious} color={C.warning} sub={total ? `${Math.round(suspicious / total * 100)}% del total` : ""} />
            <StatCard label="Limpios" value={clean} color={C.success} sub={total ? `${Math.round(clean / total * 100)}% del total` : ""} />
          </div>
          <div style={{ display: "flex", gap: 16, marginBottom: 24 }}>
            <div style={{ flex: 1, background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, padding: "18px 20px" }}>
              <div style={{ fontSize: 12, color: C.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>Distribución de veredictos</div>
              {total > 0 ? (
                <PieChart width={240} height={180} style={{ margin: "0 auto" }}>
                  <Pie data={pieData} cx={120} cy={90} innerRadius={50} outerRadius={75} dataKey="value" stroke="none">
                    {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12, color: C.text }} />
                </PieChart>
              ) : <p style={{ color: C.textMuted, fontSize: 13 }}>Sin datos aún</p>}
              <div style={{ marginTop: 8 }}>
                {pieData.map(e => (
                  <div key={e.name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <div style={{ width: 8, height: 8, borderRadius: 2, background: e.color }} />
                      <span style={{ fontSize: 12, color: C.textMuted }}>{e.name}</span>
                    </div>
                    <span style={{ fontSize: 12, color: e.color, fontFamily: "monospace" }}>{e.value}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ flex: 2, background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, padding: "18px 20px" }}>
              <div style={{ fontSize: 12, color: C.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>Análisis recientes</div>
              {tasks.slice(0, 6).map(t => (
                <div key={t.id} onClick={() => { setSelectedTask(t); setView("report"); }} style={{ display: "flex", alignItems: "center", gap: 12, padding: "9px 0", borderBottom: `1px solid ${C.border}`, cursor: "pointer" }}
                  onMouseEnter={e => e.currentTarget.style.opacity = "0.8"}
                  onMouseLeave={e => e.currentTarget.style.opacity = "1"}>
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: C.accent, minWidth: 32 }}>#{t.id}</span>
                  <span style={{ fontSize: 12, color: C.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.name}</span>
                  <VerdictBadge v={t.verdict} />
                  <ScoreMeter score={t.score} />
                </div>
              ))}
              {tasks.length === 0 && <p style={{ color: C.textMuted, fontSize: 13 }}>Sin análisis todavía.</p>}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function SubmitView({ setView, setSelectedTask, refreshTasks }) {
  const [tab, setTab] = useState("file");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [analysisTimeout, setAnalysisTimeout] = useState("120");
  const [pkg, setPkg] = useState("");
  const tabs = [
    { id: "file", label: "Archivo" },
    { id: "url", label: "URL" },
    { id: "pcap", label: "PCAP" },
    { id: "dlexec", label: "DL & Exec" },
  ];

  const getCsrfToken = () => {
    const match = document.cookie
      .split(";")
      .map(c => c.trim())
      .find(c => c.startsWith("csrftoken="));
    return match ? match.split("=")[1] : "";
  };

  const handleSubmit = async () => {
    setError("");
    setLoading(true);
    try {
      const csrfToken = getCsrfToken();
      let endpoint = "";
      const fd = new FormData();

      if (tab === "file" || tab === "pcap") {
        if (!file) { setError("Selecciona un archivo primero."); setLoading(false); return; }
        // CAPE APIv2 espera el campo como "file", no "sample"
        fd.append("file", file, file.name);
        if (analysisTimeout) fd.append("timeout", analysisTimeout);
        if (pkg) fd.append("package", pkg);
        endpoint = tab === "pcap" ? "/apiv2/tasks/create/pcap/" : "/apiv2/tasks/create/file/";
      } else {
        if (!url) { setError("Introduce una URL."); setLoading(false); return; }
        fd.append("url", url);
        if (analysisTimeout) fd.append("timeout", analysisTimeout);
        endpoint = tab === "url" ? "/apiv2/tasks/create/url/" : "/apiv2/tasks/create/dlnexec/";
      }

      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "X-CSRFToken": csrfToken },
        body: fd,
      });

      // Detectar errores HTTP antes de parsear JSON
      if (!res.ok) {
        const text = await res.text();
        setError(`Error HTTP ${res.status}: ${text.slice(0, 200)}`);
        setLoading(false);
        return;
      }

      const data = await res.json();

      if (data.error) { setError(String(data.error)); setLoading(false); return; }

      // CAPE puede devolver task_id (singular) o task_ids[0] según la versión
      const taskId = data.data?.task_ids?.[0] ?? data.data?.task_id ?? null;

      if (taskId) {
        await refreshTasks();
        setSelectedTask({
          id: taskId,
          name: file?.name || url || "Análisis",
          verdict: "unknown",
          score: 0,
          type: tab,
          time: new Date().toLocaleString("es"),
          tags: [], network: [], behaviors: [], files: [], mitre: [],
        });
        setView("report");
      } else {
        setError(`Tarea enviada pero no se pudo obtener el ID. Respuesta: ${JSON.stringify(data).slice(0, 300)}`);
      }
    } catch (e) {
      setError("Error de conexión con CAPE: " + e.message);
    }
    setLoading(false);
  };
  return (
    <div style={{ padding: 28, maxWidth: 800 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Nuevo análisis</h1>
        <p style={{ color: C.textMuted, fontSize: 13, margin: "4px 0 0" }}>Envía una muestra para analizar en la sandbox</p>
      </div>
      <div style={{ background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, overflow: "hidden" }}>
        <div style={{ display: "flex", borderBottom: `1px solid ${C.border}` }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{ padding: "14px 24px", background: tab === t.id ? "#00c8ff15" : "transparent", borderBottom: tab === t.id ? "2px solid #00c8ff" : "2px solid transparent", border: "none", borderRadius: 0, color: tab === t.id ? C.accent : C.textMuted, cursor: "pointer", fontSize: 13, fontWeight: tab === t.id ? 600 : 400 }}>{t.label}</button>
          ))}
        </div>
        <div style={{ padding: 24 }}>
          {(tab === "file" || tab === "pcap") && (
            <label style={{ display: "block", border: `2px dashed ${C.border}`, borderRadius: 8, padding: "40px 20px", textAlign: "center", cursor: "pointer" }}
              onMouseEnter={e => e.currentTarget.style.borderColor = C.accent}
              onMouseLeave={e => e.currentTarget.style.borderColor = C.border}>
              <div style={{ fontSize: 32, marginBottom: 8 }}>{tab === "pcap" ? "🔌" : "⊕"}</div>
              <div style={{ color: C.text, fontSize: 14, marginBottom: 4 }}>{file ? file.name : "Arrastra o haz clic para seleccionar"}</div>
              <div style={{ color: C.textMuted, fontSize: 12 }}>{tab === "pcap" ? ".pcap, .pcapng" : "exe, dll, doc, pdf, zip, js..."}</div>
              <input type="file" style={{ display: "none" }} accept={tab === "pcap" ? ".pcap,.pcapng" : undefined} onChange={e => setFile(e.target.files[0])} />
            </label>
          )}
          {(tab === "url" || tab === "dlexec") && (
            <div>
              <label style={{ display: "block", fontSize: 12, color: C.textMuted, marginBottom: 8 }}>{tab === "url" ? "URL a analizar" : "URL del ejecutable a descargar"}</label>
              <input value={url} onChange={e => setUrl(e.target.value)} placeholder={tab === "url" ? "https://sitio-sospechoso.com" : "https://servidor/malware.exe"}
                style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: "10px 14px", color: C.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
          )}
          <div style={{ marginTop: 20, padding: "16px 0", borderTop: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 12, color: C.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Opciones avanzadas</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div>
                <label style={{ display: "block", fontSize: 11, color: C.textMuted, marginBottom: 4 }}>Timeout (seg)</label>
                <input value={analysisTimeout} onChange={e => setAnalysisTimeout(e.target.value)} style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} />
              </div>
              <div>
                <label style={{ display: "block", fontSize: 11, color: C.textMuted, marginBottom: 4 }}>Paquete de análisis</label>
                <input value={pkg} onChange={e => setPkg(e.target.value)} placeholder="auto" style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} />
              </div>
            </div>
          </div>
          {error && <div style={{ background: "#ff3b3b15", border: "1px solid #ff3b3b40", borderRadius: 6, padding: "10px 14px", color: "#ff6060", fontSize: 13, marginTop: 12 }}>{error}</div>}
          <button onClick={handleSubmit} disabled={loading} style={{ marginTop: 16, width: "100%", padding: "13px 0", background: loading ? C.accentDim : C.accent, border: "none", borderRadius: 6, color: "#000", fontWeight: 700, fontSize: 14, cursor: loading ? "not-allowed" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
            {loading ? <><Spinner /> Enviando a CAPE...</> : "⊕  Iniciar análisis"}
          </button>
        </div>
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

function AnalysesView({ setView, setSelectedTask, tasks, loading }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const filtered = tasks.filter(t =>
    (filter === "all" || t.verdict === filter) &&
    (t.name.toLowerCase().includes(search.toLowerCase()) || (t.family || "").toLowerCase().includes(search.toLowerCase()))
  );
  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 24, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Análisis</h1>
          <p style={{ color: C.textMuted, fontSize: 13, margin: "4px 0 0" }}>{tasks.length} análisis en total</p>
        </div>
        <button onClick={() => setView("submit")} style={{ background: C.accent, border: "none", borderRadius: 6, color: "#000", fontWeight: 700, fontSize: 13, padding: "9px 18px", cursor: "pointer" }}>⊕ Nuevo análisis</button>
      </div>
      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Buscar por nombre o familia..." style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "9px 14px", color: C.text, fontSize: 13, outline: "none" }} />
        {["all", "malicious", "suspicious", "clean"].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{ padding: "9px 16px", borderRadius: 6, fontSize: 12, fontWeight: filter === f ? 700 : 400, cursor: "pointer", border: filter === f ? `1px solid ${C.pillText[f] || C.accent}` : `1px solid ${C.border}`, background: filter === f ? `${(C.pillText[f] || C.accent)}20` : C.card, color: filter === f ? (C.pillText[f] || C.accent) : C.textMuted, textTransform: "capitalize" }}>
            {f === "all" ? "Todos" : f}
          </button>
        ))}
      </div>
      {loading ? (
        <div style={{ display: "flex", alignItems: "center", gap: 10, color: C.textMuted, padding: 40 }}><Spinner /> Cargando análisis de CAPE...</div>
      ) : (
        <div style={{ background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#00c8ff08" }}>
                {["ID", "Nombre", "Tipo", "Familia", "Veredicto", "Score", "Estado", "Fecha"].map(h => (
                  <th key={h} style={{ padding: "11px 16px", textAlign: "left", fontSize: 11, color: C.textMuted, fontWeight: 500, letterSpacing: 1, textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={8} style={{ padding: 32, textAlign: "center", color: C.textMuted, fontSize: 13 }}>Sin resultados</td></tr>
              )}
              {filtered.map(t => (
                <tr key={t.id} onClick={() => { setSelectedTask(t); setView("report"); }} style={{ borderTop: `1px solid ${C.border}`, cursor: "pointer" }}
                  onMouseEnter={e => e.currentTarget.style.background = "#00c8ff08"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                  <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: 12, color: C.accent }}>#{t.id}</td>
                  <td style={{ padding: "12px 16px", fontSize: 13, color: C.text, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.name}</td>
                  <td style={{ padding: "12px 16px" }}><span style={{ background: "#00c8ff15", color: C.accent, padding: "2px 8px", borderRadius: 4, fontSize: 11, textTransform: "uppercase" }}>{t.type}</span></td>
                  <td style={{ padding: "12px 16px", fontSize: 12, fontFamily: "monospace", color: t.family ? C.warning : C.textMuted }}>{t.family || "—"}</td>
                  <td style={{ padding: "12px 16px" }}><VerdictBadge v={t.verdict} /></td>
                  <td style={{ padding: "12px 16px" }}><ScoreMeter score={t.score} /></td>
                  <td style={{ padding: "12px 16px", fontSize: 11, color: C.textMuted }}>{t.status}</td>
                  <td style={{ padding: "12px 16px", fontSize: 11, color: C.textMuted, fontFamily: "monospace" }}>{t.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

function ReportView({ task, setView }) {
  const [section, setSection] = useState("summary");
  const [report, setReport] = useState(null);
  const [loadingReport, setLoadingReport] = useState(true);
  const [aiReport, setAiReport] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [showAI, setShowAI] = useState(false);
  const [progress, setProgress] = useState(0);

  // Temporización de análisis (envío → CAPE termina)
  const [analysisElapsed, setAnalysisElapsed] = useState(0);
  const [analysisTotal, setAnalysisTotal] = useState(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const analysisStartRef = useRef(null);
  const analysisTimerRef = useRef(null);
  const analysisPollRef = useRef(null);

  // Temporización de generación de informe IA
  const [reportGenElapsed, setReportGenElapsed] = useState(null);
  const reportGenStartRef = useRef(null);

  // Carga automática del informe IA guardado en disco al abrir la tarea
  useEffect(() => {
    if (!task?.id) return;
    setAiReport("");
    setShowAI(false);
    setProgress(0);
    fetch(`/llm-api/report/${task.id}/load`)
      .then(r => r.ok ? r.text() : Promise.reject())
      .then(text => { if (text) { setAiReport(text); setShowAI(true); setProgress(100); } })
      .catch(() => {}); // Sin informe guardado — mostrar botón de generar
  }, [task?.id]);

  useEffect(() => {
    if (!task) return;
    setLoadingReport(true);
    setReport(null);
    setSection("summary");

    // Limpiar temporizadores previos
    if (analysisTimerRef.current) clearInterval(analysisTimerRef.current);
    if (analysisPollRef.current) clearInterval(analysisPollRef.current);
    analysisStartRef.current = null;
    setAnalysisRunning(false);
    setAnalysisTotal(null);
    setAnalysisElapsed(0);
    setReportGenElapsed(null);

    // Las tareas recién enviadas vienen con verdict "unknown" y score 0
    const isFresh = task.verdict === "unknown" && task.score === 0;
    let firstFetchDone = false;

    const onReady = (data) => {
      setReport(normalizeReport(data, task.id));
      if (analysisPollRef.current) { clearInterval(analysisPollRef.current); analysisPollRef.current = null; }
      if (analysisTimerRef.current) { clearInterval(analysisTimerRef.current); analysisTimerRef.current = null; }
      if (analysisStartRef.current) {
        setAnalysisTotal(Math.floor((Date.now() - analysisStartRef.current) / 1000));
        analysisStartRef.current = null;
      }
      setAnalysisRunning(false);
      setLoadingReport(false);
    };

    const tryLoad = () =>
      fetch(`/apiv2/tasks/get/report/${task.id}/`)
        .then(r => r.json())
        .then(data => {
          if (data && !data.error) {
            onReady(data);
          } else if (!firstFetchDone) {
            setReport(isFresh ? null : task);
            setLoadingReport(false);
          }
          firstFetchDone = true;
        })
        .catch(() => {
          if (!firstFetchDone) {
            setReport(isFresh ? null : task);
            setLoadingReport(false);
          }
          firstFetchDone = true;
        });

    if (isFresh) {
      // Iniciar temporizador de análisis y polling hasta que CAPE termine
      analysisStartRef.current = Date.now();
      setAnalysisRunning(true);
      analysisTimerRef.current = setInterval(() => {
        setAnalysisElapsed(Math.floor((Date.now() - analysisStartRef.current) / 1000));
      }, 1000);
      tryLoad();
      analysisPollRef.current = setInterval(tryLoad, 5000);
    } else {
      tryLoad();
    }

    return () => {
      if (analysisTimerRef.current) clearInterval(analysisTimerRef.current);
      if (analysisPollRef.current) clearInterval(analysisPollRef.current);
    };
  }, [task?.id]);

  const t = report || task;
  if (!t) return <div style={{ padding: 28, color: C.textMuted }}>Selecciona un análisis</div>;

  // Renderiza el texto Markdown del LLM en HTML estilizado
  const sectionIcons = ["📋","🔬","⚙️","🌐","🎯","📦","⚠️"];
  const accentForSection = (n) => n === 7 ? "#f87171" : n === 5 ? "#a78bfa" : n === 4 ? "#34d399" : n === 3 ? "#fb923c" : C.accent;

  // Convierte una línea con **negrita** en nodos React
  const parseBold = (line, i) => {
    const pts = line.split(/\*\*(.+?)\*\*/g);
    if (pts.length === 1) return line;
    return pts.map((p, j) => j % 2 === 1
      ? <strong key={j} style={{ color: "#e2e8f0", background: "#ffffff12", padding: "1px 5px", borderRadius: 3, fontWeight: 700 }}>{p}</strong>
      : p);
  };

  // Renderiza las líneas de contenido dentro de una sección
  const renderLines = (text, ac) => (text || "").split("\n").map((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return <div key={i} style={{ height: 4 }} />;
    // Bullet: -, *, • (el LLM puede usar cualquiera)
    const bulletMatch = trimmed.match(/^[-*•]\s+(.*)$/);
    if (bulletMatch) {
      const content = bulletMatch[1];
      const isCrit = /críti|peligro|malici|ransomware|troyano|backdoor|exploit/i.test(content);
      const isWarn = /sospecho|detecta|modific|registry|inyecc|persist|privil/i.test(content);
      const bc = isCrit ? "#f87171" : isWarn ? "#f59e0b" : ac + "80";
      return (
        <div key={i} style={{ display: "flex", gap: 8, padding: "5px 10px", marginTop: 3, borderRadius: 6, background: isCrit ? "#f8717108" : isWarn ? "#f59e0b06" : "#ffffff04", borderLeft: `2px solid ${bc}` }}>
          <span style={{ color: bc, flexShrink: 0, fontSize: 8, marginTop: 6 }}>▶</span>
          <span style={{ fontSize: 12, color: isCrit ? "#fca5a5" : C.text, lineHeight: 1.75 }}>{parseBold(content, i)}</span>
        </div>
      );
    }
    // Sub-cabeceras ### o **Título:**
    if (trimmed.startsWith("### ") || trimmed.startsWith("## ")) {
      const txt = trimmed.replace(/^#{2,3}\s+/, "");
      return <div key={i} style={{ color: "#f59e0b", fontWeight: 700, fontSize: 11, marginTop: 12, marginBottom: 3, textTransform: "uppercase", letterSpacing: 1 }}>{txt}</div>;
    }
    // Línea que es solo negrita (subtítulo inline)
    if (trimmed.match(/^\*\*[^*]+:\*\*$/)) {
      return <div key={i} style={{ color: ac, fontWeight: 700, fontSize: 12, marginTop: 10, marginBottom: 2 }}>{trimmed.replace(/\*\*/g, "")}</div>;
    }
    return <div key={i} style={{ fontSize: 12, color: C.textMuted, lineHeight: 1.75, marginTop: 2, paddingLeft: 2 }}>{parseBold(trimmed, i)}</div>;
  });

  const renderMarkdown = (text) => {
    if (!text) return null;
    // Dividir en bloques por cabeceras numéricas (flexibles: "1. **X**" o "1. X")
    const lines = text.split("\n");
    const sections = [];
    let cur = null;
    for (const line of lines) {
      const hm = line.trim().match(/^(\d+)\.\s+\*{0,2}(.+?)\*{0,2}\s*$/);
      if (hm && parseInt(hm[1]) <= 10) {
        if (cur) sections.push(cur);
        cur = { num: parseInt(hm[1]), title: hm[2].replace(/\*/g,"").trim(), lines: [] };
      } else if (cur) {
        cur.lines.push(line);
      } else {
        // Texto antes de la primera sección
        if (!sections.length || sections[0].num !== 0)
          sections.unshift({ num: 0, title: "", lines: [] });
        sections[0].lines.push(line);
      }
    }
    if (cur) sections.push(cur);

    return sections.map((sec, si) => {
      if (sec.num === 0) {
        const txt = sec.lines.join("\n").trim();
        return txt ? <div key={si} style={{ color: C.textMuted, fontSize: 12, marginBottom: 10 }}>{renderLines(txt, C.accent)}</div> : null;
      }
      const ac = accentForSection(sec.num);
      const icon = sectionIcons[(sec.num - 1) % sectionIcons.length];
      return (
        <div key={si} style={{ background: `linear-gradient(135deg,${ac}08 0%,#080f1c 100%)`, border: `1px solid ${ac}30`, borderRadius: 10, padding: "16px 20px", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, paddingBottom: 9, borderBottom: `1px solid ${ac}20` }}>
            <div style={{ width: 28, height: 28, borderRadius: 7, background: `${ac}20`, border: `1px solid ${ac}50`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, flexShrink: 0 }}>{icon}</div>
            <span style={{ color: ac, fontWeight: 700, fontSize: 14 }}>{sec.title}</span>
          </div>
          {renderLines(sec.lines.join("\n"), ac)}
        </div>
      );
    });
  };

  const downloadReport = () => {
    const blob = new Blob([aiReport], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `informe_IA_${t.name.replace(/[^a-z0-9.]/gi, "_")}_${t.id}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const generateAIReport = async () => {
    reportGenStartRef.current = Date.now();
    setReportGenElapsed(null);
    setAiLoading(true);
    setAiReport("");
    setShowAI(true);
    setProgress(0);
    const EXPECTED_CHARS = 5500;
    try {
      const res = await fetch(`/llm-api/report/${t.id}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let fullText = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        fullText += decoder.decode(value, { stream: true });
        setAiReport(fullText);
        setProgress(Math.min(95, Math.round((fullText.length / EXPECTED_CHARS) * 100)));
      }
      setProgress(100);
      if (!fullText) setAiReport("No se generó contenido. Verifica que Ollama esté en ejecución.");
    } catch (e) {
      setAiReport(`❌ Error: ${e.message}\n\nAsegúrate de que el servidor API está ejecutándose:\nsudo /home/nuria/llm/venv/bin/python3 /home/nuria/SCRIPTDEFINITIVOS/api_server_final.py`);
    }
    setReportGenElapsed(((Date.now() - reportGenStartRef.current) / 1000).toFixed(1));
    setAiLoading(false);
  };

  const sections = ["summary", "network", "behaviors", "files", "mitre"];
  const sectionLabels = { summary: "Resumen", network: "Red", behaviors: "Comportamiento", files: "Archivos", mitre: "MITRE ATT&CK" };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
        <button onClick={() => setView("analyses")} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 4, color: C.textMuted, cursor: "pointer", padding: "6px 12px", fontSize: 12 }}>← Volver</button>
        <div>
          <h1 style={{ color: C.text, fontSize: 18, fontWeight: 700, margin: 0, fontFamily: "monospace" }}>{t.name}</h1>
          <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 4 }}>
            <VerdictBadge v={t.verdict} />
            <ScoreMeter score={t.score} />
            {t.family && <span style={{ fontSize: 12, color: C.warning, fontFamily: "monospace" }}>{t.family}</span>}
            <span style={{ fontSize: 11, color: C.textMuted }}>#{t.id} · {t.time}</span>
            {loadingReport && <><Spinner /><span style={{ fontSize: 11, color: C.textMuted, marginLeft: 4 }}>Cargando informe...</span></>}
            {analysisRunning && (
              <span style={{ fontSize: 11, color: C.warning, background: "#ffb80015", padding: "2px 10px", borderRadius: 4, fontFamily: "monospace" }}>
                ⏱ Analizando: {fmtSeconds(analysisElapsed)}
              </span>
            )}
            {analysisTotal !== null && (
              <span style={{ fontSize: 11, color: C.success, background: "#00d87815", padding: "2px 10px", borderRadius: 4, fontFamily: "monospace" }}>
                ✓ Análisis en {fmtSeconds(analysisTotal)}
              </span>
            )}
          </div>
        </div>
      </div>
      {t.sha256 && (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: "10px 14px", marginBottom: 20, fontFamily: "monospace", fontSize: 11, color: C.textMuted, display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <span style={{ wordBreak: "break-all" }}>SHA256: <span style={{ color: C.text }}>{t.sha256}</span></span>
          {(t.osintLinks || []).length > 0 && (
            <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
              {t.osintLinks.map(l => (
                <a key={l.label} href={l.url} target="_blank" rel="noreferrer" title={`Buscar este hash en ${l.name}`}
                  style={{ background: l.color + "20", color: l.color, border: `1px solid ${l.color}50`, borderRadius: 4, padding: "3px 10px", fontSize: 10, fontWeight: 700, textDecoration: "none", letterSpacing: 0.3, transition: "all 0.15s" }}
                  onMouseEnter={e => { e.currentTarget.style.background = l.color + "35"; }}
                  onMouseLeave={e => { e.currentTarget.style.background = l.color + "20"; }}>
                  {l.label}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
      {/* ── BLOQUE IA ── */}
      <div style={{ background: "linear-gradient(135deg, #0a1628 0%, #0d1f35 100%)", border: "1px solid #00c8ff30", borderRadius: 12, padding: 24, marginBottom: 20 }}>
        {/* Cabecera */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: showAI ? 20 : 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: "linear-gradient(135deg,#00c8ff20,#0066ff30)", border: "1px solid #00c8ff40", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20 }}>🧠</div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: C.accent, letterSpacing: 0.3 }}>Informe generado por IA</div>
              <div style={{ fontSize: 11, color: C.textMuted, marginTop: 1 }}>Análisis automático con Llama 3 · Modelo local · Sin envío de datos</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            {aiReport && !aiLoading && (
              <button onClick={downloadReport} title="Descargar informe en Markdown" style={{ background: "transparent", border: `1px solid #00c8ff40`, borderRadius: 8, color: C.accent, fontWeight: 600, fontSize: 13, padding: "10px 16px", cursor: "pointer", display: "flex", alignItems: "center", gap: 8, transition: "all 0.2s" }}
                onMouseEnter={e => { e.currentTarget.style.background = "#00c8ff15"; }}
                onMouseLeave={e => { e.currentTarget.style.background = "transparent"; }}>
                ⬇ Descargar
              </button>
            )}
            <button onClick={generateAIReport} disabled={aiLoading} style={{ background: aiLoading ? "transparent" : "linear-gradient(135deg,#00c8ff,#0066ff)", border: aiLoading ? `1px solid ${C.border}` : "none", borderRadius: 8, color: aiLoading ? C.textMuted : "#000", fontWeight: 700, fontSize: 13, padding: "10px 20px", cursor: aiLoading ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: 8, transition: "all 0.2s" }}>
              {aiLoading ? <><Spinner /> Generando...</> : aiReport ? "↺ Regenerar" : "✦ Generar informe"}
            </button>
          </div>
        </div>

        {/* Barra de progreso */}
        {aiLoading && (
          <div style={{ marginBottom: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span style={{ fontSize: 11, color: C.textMuted }}>
                {progress < 15 ? "📂 Leyendo datos del análisis..." : progress < 35 ? "🔍 Analizando comportamientos..." : progress < 60 ? "✍️ Generando el informe..." : progress < 80 ? "🎯 Documentando TTPs MITRE..." : "🏁 Finalizando el análisis..."}
              </span>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.accent, fontFamily: "monospace" }}>{progress}%</span>
            </div>
            <div style={{ height: 6, background: "#0a1628", borderRadius: 99, overflow: "hidden", border: "1px solid #00c8ff20" }}>
              <div style={{ height: "100%", width: `${progress}%`, background: "linear-gradient(90deg,#0066ff,#00c8ff)", borderRadius: 99, transition: "width 0.4s ease", boxShadow: "0 0 8px #00c8ff60" }} />
            </div>
          </div>
        )}

        {/* Informe generado */}
        {showAI && (
          <div style={{ marginTop: 20 }}>
            {!aiLoading && reportGenElapsed !== null && (
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 12, fontSize: 11, color: C.textMuted }}>
                <span>⏱</span>
                <span>Informe generado en <span style={{ color: C.accent, fontFamily: "monospace", fontWeight: 700 }}>{reportGenElapsed}s</span></span>
              </div>
            )}
            {aiLoading && !aiReport
              ? <div style={{ display: "flex", alignItems: "center", gap: 10, color: C.textMuted, fontSize: 13, padding: "12px 0" }}><Spinner /> Llama 3 está procesando la muestra...</div>
              : <div style={{ color: C.text, fontSize: 13, lineHeight: 1.8 }}>{renderMarkdown(aiReport)}</div>}
          </div>
        )}

      </div>
      <div style={{ background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, overflow: "hidden" }}>
        <div style={{ display: "flex", borderBottom: `1px solid ${C.border}` }}>
          {sections.map(s => (
            <button key={s} onClick={() => setSection(s)} style={{ padding: "12px 18px", background: section === s ? "#00c8ff15" : "transparent", borderBottom: section === s ? "2px solid #00c8ff" : "2px solid transparent", border: "none", borderRadius: 0, color: section === s ? C.accent : C.textMuted, cursor: "pointer", fontSize: 12, fontWeight: section === s ? 600 : 400 }}>
              {sectionLabels[s]}
            </button>
          ))}
        </div>
        <div style={{ padding: 20 }}>
          {section === "summary" && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
                {[["Tipo", t.type?.toUpperCase() || "N/A"], ["Plataforma", t.platform || "N/A"], ["Familia", t.family || "Desconocida"], ["Fecha", t.time || "N/A"]].map(([k, v]) => (
                  <div key={k} style={{ background: C.surface, borderRadius: 6, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.textMuted, textTransform: "uppercase", marginBottom: 4 }}>{k}</div>
                    <div style={{ fontSize: 14, color: C.text, fontFamily: "monospace" }}>{v}</div>
                  </div>
                ))}
              </div>
              {(t.tags || []).length > 0 && (
                <div>
                  <div style={{ fontSize: 11, color: C.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Tags</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {t.tags.map(tag => <span key={tag} style={{ background: C.surface, border: `1px solid ${C.border}`, color: C.warning, padding: "3px 10px", borderRadius: 4, fontSize: 12 }}>{tag}</span>)}
                  </div>
                </div>
              )}
            </div>
          )}
          {section === "network" && (() => {
            const n = t.network || {};
            const realTotal = (arr) => arr?.__total ?? arr?.length ?? 0;
            const counts = [
              ["Hosts", realTotal(n.hosts)], ["Dominios", realTotal(n.domains)],
              ["DNS", realTotal(n.dns)], ["HTTP", realTotal(n.http)],
              ["TCP", realTotal(n.tcp)], ["UDP", realTotal(n.udp)],
            ];
            const total = counts.reduce((a, [, c]) => a + c, 0);
            const Row = ({ children }) => <div style={{ background: C.surface, borderRadius: 6, padding: "9px 14px", marginBottom: 6, display: "flex", alignItems: "center", gap: 12, fontFamily: "monospace", fontSize: 12 }}>{children}</div>;
            const Tag = ({ c, children }) => <span style={{ background: c + "20", color: c, padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, minWidth: 42, textAlign: "center", flexShrink: 0 }}>{children}</span>;
            const Truncated = ({ arr }) => realTotal(arr) > (arr?.length || 0) ? (
              <div style={{ fontSize: 10, color: C.textMuted, fontStyle: "italic", marginBottom: 10 }}>Mostrando los primeros {arr.length} de {realTotal(arr)} registros.</div>
            ) : null;
            return total > 0 ? (
              <div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 18 }}>
                  {counts.map(([k, c]) => (
                    <div key={k} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: "8px 14px", minWidth: 80 }}>
                      <div style={{ fontSize: 18, fontWeight: 700, color: c > 0 ? C.accent : C.textMuted, fontFamily: "monospace" }}>{c}</div>
                      <div style={{ fontSize: 10, color: C.textMuted, textTransform: "uppercase" }}>{k}</div>
                    </div>
                  ))}
                </div>

                {n.hosts?.length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Hosts contactados ({realTotal(n.hosts)})</div>
                  <Truncated arr={n.hosts} />
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 18 }}>
                    {n.hosts.map((h, i) => <span key={i} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "4px 10px", fontFamily: "monospace", fontSize: 11, color: C.accent }}>{h}</span>)}
                  </div>
                </>}

                {n.domains?.length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Dominios ({realTotal(n.domains)})</div>
                  <Truncated arr={n.domains} />
                  {n.domains.map((d, i) => <Row key={i}><Tag c={C.warning}>DOM</Tag><span style={{ color: C.text }}>{d.domain}</span>{d.ip && <span style={{ color: C.textMuted }}>→ {d.ip}</span>}</Row>)}
                  <div style={{ height: 12 }} />
                </>}

                {n.dns?.length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Consultas DNS ({realTotal(n.dns)})</div>
                  <Truncated arr={n.dns} />
                  {n.dns.map((d, i) => <Row key={i}><Tag c="#00c8ff">{d.type}</Tag><span style={{ color: C.text }}>{d.request}</span>{d.answers.length > 0 && <span style={{ color: C.textMuted }}>→ {d.answers.join(", ")}</span>}</Row>)}
                  <div style={{ height: 12 }} />
                </>}

                {n.http?.length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Peticiones HTTP ({realTotal(n.http)})</div>
                  <Truncated arr={n.http} />
                  {n.http.map((h, i) => <Row key={i}><Tag c={C.danger}>{h.method}</Tag><span style={{ color: C.text }}>{h.host}</span><span style={{ color: C.textMuted, wordBreak: "break-all" }}>{h.uri}</span></Row>)}
                  <div style={{ height: 12 }} />
                </>}

                {n.tcp?.length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Conexiones TCP ({realTotal(n.tcp)})</div>
                  <Truncated arr={n.tcp} />
                  {n.tcp.map((c, i) => <Row key={i}><Tag c="#34d399">TCP</Tag><span style={{ color: C.text }}>{c.src}:{c.sport}</span><span style={{ color: C.textMuted }}>→</span><span style={{ color: C.text }}>{c.dst}:{c.dport}</span></Row>)}
                  <div style={{ height: 12 }} />
                </>}

                {n.udp?.length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Conexiones UDP ({realTotal(n.udp)})</div>
                  <Truncated arr={n.udp} />
                  {n.udp.map((c, i) => <Row key={i}><Tag c="#a78bfa">UDP</Tag><span style={{ color: C.text }}>{c.src}:{c.sport}</span><span style={{ color: C.textMuted }}>→</span><span style={{ color: C.text }}>{c.dst}:{c.dport}</span></Row>)}
                </>}
              </div>
            ) : <p style={{ color: C.textMuted, fontSize: 13 }}>{loadingReport ? "Cargando..." : "No se detectó tráfico de red."}</p>;
          })()}
          {section === "behaviors" && (() => {
            const procs = t.processes || [];
            const bs = t.behaviorSummary || {};
            const realTotal = (arr) => arr?.__total ?? arr?.length ?? 0;
            const TruncNote = ({ arr }) => realTotal(arr) > (arr?.length || 0) ? (
              <div style={{ fontSize: 10, color: C.textMuted, fontStyle: "italic", marginBottom: 8 }}>Mostrando los primeros {arr.length} de {realTotal(arr)} registros.</div>
            ) : null;
            const summaryGroups = [
              ["Comandos ejecutados", bs.commands, C.danger],
              ["Claves de registro modificadas", bs.keysWritten, C.warning],
              ["Claves de registro leídas", bs.keysRead, C.textMuted],
              ["Archivos escritos", bs.filesWritten, C.warning],
              ["Archivos leídos", bs.filesRead, C.textMuted],
              ["Archivos eliminados", bs.filesDeleted, C.danger],
              ["Mutexes creados", bs.mutexes, C.accent],
              ["DLLs cargadas", bs.dllsLoaded, C.textMuted],
            ].filter(([, arr]) => arr && arr.length > 0);
            const hasAny = (t.behaviors || []).length > 0 || procs.length > 0 || summaryGroups.length > 0;
            return hasAny ? (
              <div>
                {(t.behaviors || []).length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 10, textTransform: "uppercase", letterSpacing: 1 }}>Detecciones ({realTotal(t.behaviors)})</div>
                  <TruncNote arr={t.behaviors} />
                  {t.behaviors.map((b, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "9px 0", borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ color: b.severity >= 3 ? C.danger : C.warning, fontSize: 14, marginTop: 1, flexShrink: 0 }}>⚠</span>
                      <div><span style={{ fontSize: 13, color: C.text }}>{b.description || b.name}</span>{b.name && b.description && <span style={{ display: "block", fontSize: 10, color: C.textMuted, fontFamily: "monospace", marginTop: 2 }}>{b.name}</span>}</div>
                    </div>
                  ))}
                  <div style={{ height: 18 }} />
                </>}

                {procs.length > 0 && <>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 10, textTransform: "uppercase", letterSpacing: 1 }}>Árbol de procesos ({realTotal(procs)})</div>
                  <TruncNote arr={procs} />
                  {procs.map((p, i) => (
                    <div key={i} style={{ background: C.surface, borderRadius: 6, padding: "10px 14px", marginBottom: 6, display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                      <span style={{ fontFamily: "monospace", fontSize: 12, fontWeight: 700, color: C.accent }}>{p.name}</span>
                      <span style={{ fontSize: 10, color: C.textMuted }}>PID {p.pid} · PPID {p.ppid}</span>
                      {p.calls > 0 && <span style={{ fontSize: 10, color: C.warning, background: "#ffb80015", padding: "1px 8px", borderRadius: 4 }}>{p.calls} llamadas API</span>}
                      {p.path && <span style={{ fontSize: 10, color: C.textMuted, fontFamily: "monospace", wordBreak: "break-all" }}>{p.path}</span>}
                    </div>
                  ))}
                  <div style={{ height: 18 }} />
                </>}

                {summaryGroups.map(([label, arr, color]) => (
                  <div key={label} style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 11, color, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>{label} ({realTotal(arr)})</div>
                    <TruncNote arr={arr} />
                    {arr.map((item, i) => <div key={i} style={{ fontFamily: "monospace", fontSize: 11, color: C.text, background: C.surface, borderRadius: 4, padding: "6px 12px", marginBottom: 4, wordBreak: "break-all" }}>{typeof item === "string" ? item : JSON.stringify(item)}</div>)}
                  </div>
                ))}
              </div>
            ) : <p style={{ color: C.textMuted, fontSize: 13 }}>{loadingReport ? "Cargando..." : "Sin comportamientos detectados."}</p>;
          })()}
          {section === "files" && (() => {
            const realTotal = (t.files)?.__total ?? (t.files || []).length;
            return (t.files || []).length > 0 ? (
              <div>
                <div style={{ fontSize: 11, color: C.accent, fontWeight: 700, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Archivos creados ({realTotal})</div>
                {realTotal > t.files.length && (
                  <div style={{ fontSize: 10, color: C.textMuted, fontStyle: "italic", marginBottom: 8 }}>Mostrando los primeros {t.files.length} de {realTotal} registros.</div>
                )}
                {t.files.map((f, i) => (
                  <div key={i} style={{ background: C.surface, borderRadius: 4, padding: "10px 14px", marginBottom: 6, display: "flex", alignItems: "center", gap: 10, justifyContent: "space-between" }}>
                    <span style={{ fontFamily: "monospace", fontSize: 12, color: C.warning, wordBreak: "break-all" }}>{f.name}</span>
                    {f.type && <span style={{ fontSize: 10, color: C.textMuted, flexShrink: 0 }}>{f.type}</span>}
                  </div>
                ))}
              </div>
            ) : <p style={{ color: C.textMuted, fontSize: 13 }}>{loadingReport ? "Cargando..." : "No se detectaron archivos creados."}</p>;
          })()}
          {section === "mitre" && (() => {
            const fromCape = t.mitre || [];
            const fromAI = aiReport ? [...new Set((aiReport.match(/T\d{4}(?:\.\d{3})?/g) || []))] : [];
            const allTtps = [...new Set([...fromCape, ...fromAI])];
            const MitreBadge = ({ ttp }) => (
              <a href={`https://attack.mitre.org/techniques/${ttp.replace(".", "/")}/`} target="_blank" rel="noreferrer"
                style={{ display: "inline-flex", flexDirection: "column", gap: 4, background: "linear-gradient(135deg,#1a0a2e,#0d1433)", border: "1px solid #7c3aed60", borderRadius: 8, padding: "10px 14px", textDecoration: "none", transition: "all 0.2s", minWidth: 110 }}
                onMouseEnter={e => { e.currentTarget.style.background = "#7c3aed25"; e.currentTarget.style.borderColor = "#7c3aed"; e.currentTarget.style.transform = "translateY(-2px)"; }}
                onMouseLeave={e => { e.currentTarget.style.background = "linear-gradient(135deg,#1a0a2e,#0d1433)"; e.currentTarget.style.borderColor = "#7c3aed60"; e.currentTarget.style.transform = ""; }}>
                <span style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 800, color: "#a78bfa" }}>⬡ {ttp}</span>
                <span style={{ fontSize: 10, color: "#6d4ca8" }}>{fromCape.includes(ttp) ? "CAPE" : "IA"} · ATT&CK →</span>
              </a>
            );
            return allTtps.length > 0 ? (
              <div>
                <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 16 }}>
                  {fromCape.length} técnicas detectadas por CAPE
                  {fromAI.filter(x => !fromCape.includes(x)).length > 0 && ` · ${fromAI.filter(x => !fromCape.includes(x)).length} adicionales identificadas por IA`}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                  {allTtps.map(m => <MitreBadge key={m} ttp={m} />)}
                </div>
              </div>
            ) : <p style={{ color: C.textMuted, fontSize: 13 }}>{loadingReport ? "Cargando..." : "No se identificaron técnicas MITRE ATT&CK."}</p>;
          })()}
        </div>
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

function AdminView() {
  return (
    <div style={{ padding: 28, maxWidth: 600 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Configuración</h1>
        <p style={{ color: C.textMuted, fontSize: 13, margin: "4px 0 0" }}>Ajustes y estado de la sandbox</p>
      </div>
      <div style={{ background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, padding: 24, marginBottom: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 16 }}>Conexión CAPE</div>
        {[["URL de CAPE", "http://localhost:8000"], ["API Key (opcional)", ""]].map(([label, ph]) => (
          <div key={label} style={{ marginBottom: 14 }}>
            <label style={{ display: "block", fontSize: 11, color: C.textMuted, marginBottom: 5, textTransform: "uppercase", letterSpacing: 1 }}>{label}</label>
            <input defaultValue={ph} placeholder={ph || "Dejar vacío"} style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "9px 12px", color: C.text, fontSize: 13, outline: "none", boxSizing: "border-box" }} />
          </div>
        ))}
        <button style={{ background: C.accent, border: "none", borderRadius: 6, color: "#000", fontWeight: 700, fontSize: 13, padding: "9px 20px", cursor: "pointer" }}>Verificar conexión</button>
      </div>
      <div style={{ background: C.card, border: "0.5px solid #1a2d45", borderRadius: 8, padding: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 16 }}>Estado de servicios</div>
        {[["cape.service", "running"], ["cape-web.service", "running"], ["cape-processor.service", "running"], ["cape-rooter.service", "running"], ["postgresql@18-main", "running"]].map(([svc, status]) => (
          <div key={svc} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
            <span style={{ fontFamily: "monospace", fontSize: 12, color: C.text }}>{svc}</span>
            <span style={{ fontSize: 11, color: C.success, background: "#00d87815", padding: "2px 10px", borderRadius: 4, textTransform: "uppercase", fontWeight: 700 }}>{status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [view, setViewState] = useState("dashboard");
  const [selectedTask, setSelectedTaskState] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);

  // Refs para evitar closures obsoletos en setInterval y en el manejo de history
  const tasksRef = useRef([]);
  useEffect(() => { tasksRef.current = tasks; }, [tasks]);
  const isFirstRender = useRef(true);
  const isPopRef = useRef(false);
  const viewRef = useRef(view);
  const selectedTaskRef = useRef(selectedTask);
  useEffect(() => { viewRef.current = view; }, [view]);
  useEffect(() => { selectedTaskRef.current = selectedTask; }, [selectedTask]);

  // setView/setSelectedTask: React 18 agrupa en un solo render las llamadas
  // sucesivas (p.ej. setSelectedTask(t); setView("report")), así que el
  // useEffect de más abajo solo genera UNA entrada de historial, no dos.
  const setSelectedTask = (task) => setSelectedTaskState(task);
  const setView = (v) => setViewState(v);

  // Navegación con el botón atrás/adelante del navegador
  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      window.history.replaceState({ view, taskId: selectedTask?.id ?? null }, "");
      return;
    }
    if (isPopRef.current) { isPopRef.current = false; return; }
    window.history.pushState({ view, taskId: selectedTask?.id ?? null }, "");
  }, [view, selectedTask?.id]);

  useEffect(() => {
    const onPopState = (e) => {
      isPopRef.current = true;
      const state = e.state || { view: "dashboard", taskId: null };
      setViewState(state.view || "dashboard");
      if (state.taskId) {
        const found = tasksRef.current.find(x => x.id === state.taskId);
        setSelectedTaskState(found || { id: state.taskId });
      } else {
        setSelectedTaskState(null);
      }
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const fetchTasks = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await fetch("/apiv2/tasks/list/500/");
      const data = await res.json();
      const raw = Array.isArray(data.data) ? data.data : Array.isArray(data) ? data : [];
      const normalizedTasks = raw.map(normalizeTask).sort((a, b) => b.id - a.id);

      // Conservar el score ya conocido de un poll anterior para no re-pedirlo sin necesidad
      const prevTasks = tasksRef.current;
      const mergedTasks = normalizedTasks.map(nt => {
        const prev = prevTasks.find(p => p.id === nt.id);
        return prev && prev.score > 0 ? { ...nt, score: prev.score, verdict: prev.verdict } : nt;
      });
      setTasks(mergedTasks);
      tasksRef.current = mergedTasks;

      // El listado de CAPE no incluye score — lo cargamos en background solo para las que faltan
      const toScore = mergedTasks.filter(t => t.status === "reported" && (!t.score || t.score === 0));
      if (toScore.length > 0) {
        Promise.allSettled(
          toScore.map(t =>
            fetch(`/apiv2/tasks/get/report/${t.id}/`)
              .then(r => r.json())
              .then(d => ({ id: t.id, score: normalizeScore(d.malscore ?? d.info?.score ?? 0) }))
              .catch(() => ({ id: t.id, score: 0 }))
          )
        ).then(results => {
          const scores = results.filter(r => r.status === "fulfilled").map(r => r.value);
          setTasks(prev => {
            const updated = prev.map(t => {
              const s = scores.find(x => x.id === t.id);
              return s && s.score > 0 ? { ...t, score: s.score, verdict: deriveVerdict(s.score) } : t;
            });
            tasksRef.current = updated;
            return updated;
          });
        });
      }
    } catch (e) {
      console.error("Error fetching tasks:", e);
    }
    if (!silent) setLoading(false);
  };

  // Carga inicial + autorrefresco silencioso cada 6s para reflejar cambios de estado
  // (pending → running → reported) sin que el usuario tenga que recargar la página
  useEffect(() => {
    fetchTasks();
    const interval = setInterval(() => fetchTasks(true), 6000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: "flex", background: C.bg, minHeight: "100vh", fontFamily: "'Segoe UI', system-ui, sans-serif", color: C.text }}>
      <Sidebar view={view} setView={setView} />
      <div style={{ flex: 1, overflow: "auto" }}>
        {view === "dashboard" && <DashboardView setView={setView} setSelectedTask={setSelectedTask} tasks={tasks} loading={loading} />}
        {view === "submit" && <SubmitView setView={setView} setSelectedTask={setSelectedTask} refreshTasks={fetchTasks} />}
        {view === "analyses" && <AnalysesView setView={setView} setSelectedTask={setSelectedTask} tasks={tasks} loading={loading} />}
        {view === "report" && <ReportView task={selectedTask} setView={setView} />}
        {view === "admin" && <AdminView />}
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}} *{box-sizing:border-box}`}</style>
    </div>
  );
}
