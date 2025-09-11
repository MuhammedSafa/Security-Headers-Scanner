import React, { useEffect, useMemo, useState } from "react";

// API reverse-proxy: aynı origin
const API = "/api/scan";

/* ---------------- Tema ---------------- */
const THEMES = {
  dark: {
    name: "dark",
    bg: "#0b1220",
    cardBg: "#0f172a",
    inputBg: "#0b1329",
    border: "#1e293b",
    borderSoft: "#1f2a44",
    text: "#e5e7eb",
    textSoft: "#94a3b8",
    textMuted: "#cbd5e1",
    tableAlt: "#0b1329",
    link: "#93c5fd",
    topLogoFrom: "#2563eb",
    topLogoTo: "#10b981",
    shadow: "0 10px 30px rgba(0,0,0,.25)",
    overlay: "rgba(2,6,23,.6)",
    btnPrimaryBg: "#2563eb",
    btnPrimaryFg: "#fff",
    btnGhostBg: "#fff",
    btnGhostFg: "#111",
    btnGhostBd: "#e5e7eb",
    btnSubtleBg: "#f3f4f6",
    btnSubtleFg: "#111",
    btnDangerBg: "#dc2626",
    btnDangerFg: "#fff",
    thBg: "#0f172a",
  },
  light: {
    name: "light",
    bg: "#f7f7fb",
    cardBg: "#ffffff",
    inputBg: "#ffffff",
    border: "#e5e7eb",
    borderSoft: "#e5e7eb",
    text: "#111827",
    textSoft: "#6b7280",
    textMuted: "#374151",
    tableAlt: "#fafafa",
    link: "#1d4ed8",
    topLogoFrom: "#2563eb",
    topLogoTo: "#10b981",
    shadow: "0 10px 30px rgba(0,0,0,.12)",
    overlay: "rgba(0,0,0,.35)",
    btnPrimaryBg: "#2563eb",
    btnPrimaryFg: "#fff",
    btnGhostBg: "#fff",
    btnGhostFg: "#111",
    btnGhostBd: "#e5e7eb",
    btnSubtleBg: "#f3f4f6",
    btnSubtleFg: "#111",
    btnDangerBg: "#dc2626",
    btnDangerFg: "#fff",
    thBg: "#f8fafc",
  },
};

function useTheme() {
  const initial =
    typeof window !== "undefined"
      ? localStorage.getItem("secscan-theme") || "light"
      : "light";
  const [theme, setTheme] = useState(initial);
  useEffect(() => {
    localStorage.setItem("secscan-theme", theme);
  }, [theme]);
  const t = THEMES[theme] || THEMES.light;
  const toggle = () => setTheme((p) => (p === "light" ? "dark" : "light"));
  return { t, theme, setTheme, toggle };
}

/* -------------- Neumorfik Tema Anahtarı -------------- */
function ThemeToggle({ theme, setTheme }) {
  const isDark = theme === "dark";
  const w = 60, h = 28, pad = 3, knob = 22;
  const bgLight = "#f2f3f7", bgDark = "#0f172a";

  const track = {
    width: w, height: h, borderRadius: 9999,
    background: isDark ? bgDark : bgLight,
    boxShadow: isDark
      ? "inset 6px 6px 12px rgba(0,0,0,.45), inset -6px -6px 12px rgba(255,255,255,.03)"
      : "8px 8px 16px rgba(0,0,0,.08), -8px -8px 16px rgba(255,255,255,.8)",
    border: isDark ? "1px solid #1e293b" : "1px solid #e5e7eb",
    position: "relative",
    display: "flex",
    alignItems: "center",
    cursor: "pointer",
    userSelect: "none",
    transition: "background .25s ease, box-shadow .25s ease, border .25s ease",
    padding: pad,
  };
  const knobStyle = {
    position: "absolute",
    top: pad, left: isDark ? w - pad - knob : pad,
    width: knob, height: knob, borderRadius: 9999,
    background: isDark ? "#0b1220" : "#ffffff",
    boxShadow: isDark
      ? "6px 6px 12px rgba(0,0,0,.45), -4px -4px 10px rgba(255,255,255,.02)"
      : "6px 6px 12px rgba(0,0,0,.08), -6px -6px 12px rgba(255,255,255,1)",
    border: isDark ? "1px solid #1e293b" : "1px solid #e5e7eb",
    transition: "left .25s ease, background .25s ease, box-shadow .25s ease, border .25s ease",
    display: "grid", placeItems: "center",
  };
  const textStyle = (active) => ({
    flex: 1, textAlign: "center", fontWeight: 800,
    fontSize: 10, letterSpacing: ".4px",
    color: active ? (isDark ? "#fff" : "#111") : (isDark ? "#8ea0b6" : "#94a3b8"),
    transition: "color .25s ease",
  });

  const Sun = (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="4.5" stroke={isDark?"#93c5fd":"#f59e0b"} strokeWidth="2"/>
      <g stroke={isDark?"#93c5fd":"#f59e0b"} strokeWidth="2" strokeLinecap="round">
        <path d="M12 2v3"/><path d="M12 19v3"/><path d="M2 12h3"/><path d="M19 12h3"/>
        <path d="M4.6 4.6l2.1 2.1"/><path d="M17.3 17.3l2.1 2.1"/>
        <path d="M4.6 19.4l2.1-2.1"/><path d="M17.3 6.7l2.1-2.1"/>
      </g>
    </svg>
  );
  const Moon = (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M21 12.8A8.5 8.5 0 0 1 11.2 3 8.7 8.7 0 1 0 21 12.8Z"
            stroke={isDark?"#e5e7eb":"#0f172a"} strokeWidth="2" />
    </svg>
  );

  return (
    <div
      role="switch"
      aria-checked={isDark}
      onClick={() => setTheme(isDark ? "light" : "dark")}
      title={isDark ? "" : ""}
      style={track}
    >
      
      <div style={knobStyle}>{isDark ? Moon : Sun}</div>
    </div>
  );
}

/* ---------------- Küçük UI Bileşenleri ---------------- */
function Button({ children, variant = "primary", t, ...props }) {
  const base = {
    padding: "10px 14px",
    borderRadius: 10,
    fontWeight: 700,
    border: "1px solid transparent",
    cursor: "pointer",
    transition: "transform .06s ease, box-shadow .2s ease",
    whiteSpace: "nowrap",
  };
  const palette = {
    primary: { background: t.btnPrimaryBg, color: t.btnPrimaryFg },
    ghost:   { background: t.btnGhostBg, color: t.btnGhostFg, border: `1px solid ${t.btnGhostBd}` },
    subtle:  { background: t.btnSubtleBg, color: t.btnSubtleFg, border: `1px solid ${t.btnGhostBd}` },
    danger:  { background: t.btnDangerBg, color: t.btnDangerFg },
  };
  const st = { ...base, ...(palette[variant] || palette.primary) };
  return (
    <button
      {...props}
      style={{ ...st, ...(props.style || {}) }}
      onMouseDown={(e) => { e.currentTarget.style.transform = "scale(.98)"; }}
      onMouseUp={(e) => { e.currentTarget.style.transform = ""; }}
    >
      {children}
    </button>
  );
}

function Badge({ st = "info", title }) {
  const map = {
    pass: { bg:"#ecfdf5", fg:"#065f46", bd:"#a7f3d0", txt:"PASS" },
    warn: { bg:"#fff7ed", fg:"#9a3412", bd:"#fed7aa", txt:"WARN" },
    fail: { bg:"#fef2f2", fg:"#991b1b", bd:"#fecaca", txt:"FAIL" },
    info: { bg:"#f1f5f9", fg:"#334155", bd:"#e2e8f0", txt:"INFO" },
  }[st] || { bg:"#f1f5f9", fg:"#334155", bd:"#e2e8f0", txt:String(st).toUpperCase() };
  return (
    <span title={title} style={{
      display:"inline-block", padding:"3px 10px", borderRadius:999,
      background:map.bg, color:map.fg, border:`1px solid ${map.bd}`, fontWeight:700, fontSize:12
    }}>{map.txt}</span>
  );
}

function MiniBar({ counts }) {
  const total = (counts?.pass||0)+(counts?.warn||0)+(counts?.fail||0)+(counts?.info||0);
  const w=160,h=10; if(!total) return <div title="Sonuç yok" style={{width:w,height:h,background:"#eee",borderRadius:6}}/>;
  const seg=(v)=> (v/total)*w; let x=0;
  const parts=[{k:"pass",c:"#10b981"},{k:"warn",c:"#f59e0b"},{k:"fail",c:"#ef4444"},{k:"info",c:"#6b7280"}];
  return <svg width={w} height={h} aria-label={`P:${counts.pass||0} W:${counts.warn||0} F:${counts.fail||0} I:${counts.info||0}`}>
    {parts.map(p=>{const width=seg(counts[p.k]||0); const r=<rect key={p.k} x={x} y="0" width={width} height={h} fill={p.c} rx="5" ry="5"/>; x+=width; return r;})}
  </svg>;
}

/* ---------------- Utils ---------------- */
async function fetchWithTimeout(url, opts = {}, ms = 15000) {
  const ctrl = new AbortController(); const t = setTimeout(()=>ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}
function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob); const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
function csvEscape(v){ const s=(v??"").toString(); return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s; }

const EXPORT_COLUMNS = [
  { title: "Domain", fn: (r) => r.domain },
  { title: "HTTP", fn: (r) => (r.ok ? r.status : "ERR") },
  { title: "Final URL", fn: (r) => r.finalUrl || "-" },
  { title: "HSTS", fn: (r) => (r.ok ? r.checks.hsts.status : "") },
  { title: "Click", fn: (r) => (r.ok ? r.checks.click.status : "") },
  { title: "XCTO", fn: (r) => (r.ok ? r.checks.xcto.status : "") },
  { title: "Referrer", fn: (r) => (r.ok ? (r.checks.referrerPolicy?.status || r.checks.referrer?.status) : "") },
  { title: "CSP", fn: (r) => (r.ok ? r.checks.csp.status : "") },
  { title: "Perm", fn: (r) => (r.ok ? r.checks.perm.status : "") },
  { title: "COOP", fn: (r) => (r.ok ? r.checks.coop.status : "") },
  { title: "COEP", fn: (r) => (r.ok ? r.checks.coep.status : "") },
  { title: "CORP", fn: (r) => (r.ok ? r.checks.corp.status : "") },
  { title: "ACAO", fn: (r) => (r.ok ? r.checks.acao.status : "") },
  { title: "Cookies", fn: (r) => (r.ok ? r.checks.cookies.status : "") },
  { title: "Server", fn: (r) => (r.ok ? r.checks.server.status : "") },
  { title: "X-Powered-By", fn: (r) => (r.ok ? r.checks.xpb.status : "") },
  { title: "XSS", fn: (r) => (r.ok ? r.checks.xxss.status : "") },
];

function summarizeCounts(result) {
  const d = result?.checks?._details || [];
  const c = { pass:0,warn:0,fail:0,info:0 };
  for (const it of d) {
    if (it.status==="pass") c.pass++;
    else if (it.status==="warn") c.warn++;
    else if (it.status==="fail") c.fail++;
    else c.info++;
  }
  return c;
}

/* ---------------- Zafiyet Filtresi ---------------- */
const VULN_KEYS = [
  { key: "hsts",   label: "HSTS" },
  { key: "click",  label: "Clickjacking (frame-ancestors/XFO)" },
  { key: "xcto",   label: "X-Content-Type-Options" },
  { key: "referrerPolicy", label: "Referrer-Policy" },
  { key: "csp",    label: "Content-Security-Policy" },
  { key: "perm",   label: "Permissions-Policy" },
  { key: "coop",   label: "COOP" },
  { key: "coep",   label: "COEP" },
  { key: "corp",   label: "CORP" },
  { key: "acao",   label: "CORS (ACAO)" },
  { key: "cookies",label: "Set-Cookie (Secure/HttpOnly/SameSite)" },
  { key: "server", label: "Server bilgisi sızıntısı" },
  { key: "xpb",    label: "X-Powered-By sızıntısı" },
  { key: "xxss",   label: "X-XSS-Protection" },
];

function hasVulnerability(r, key, includeWarn, includeFail) {
  if (!r?.ok) return false;
  let status = key==="referrerPolicy" ? (r.checks.referrerPolicy?.status ?? r.checks.referrer?.status) : r.checks[key]?.status;
  if (!status) return false;
  return (includeFail && status==="fail") || (includeWarn && status==="warn");
}

/* ---------------- Ana Bileşen ---------------- */
export default function App() {
  const { t, theme, setTheme } = useTheme();

  const [input, setInput] = useState("example.com\ngithub.com\nwikipedia.org");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState("");
  const [rows, setRows] = useState([]);
  const [active, setActive] = useState(null);
  const [fileInfo, setFileInfo] = useState({ name: "", added: 0 });

  // Filtre durumları
  const [filterText, setFilterText] = useState("");
  const [useRegex, setUseRegex] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false); // varsayılan kapalı

  // Zafiyet filtreleri
  const [vulnSel, setVulnSel] = useState({});
  const [sevFail, setSevFail] = useState(true);
  const [sevWarn, setSevWarn] = useState(true);
  const [vulnLogic, setVulnLogic] = useState("any"); // any=OR, all=AND

  const domainFiltered = useMemo(() => {
    if (!filterText.trim()) return rows;
    const terms = filterText.split(",").map(s=>s.trim()).filter(Boolean);
    try {
      return rows.filter(r=>{
        if (!r?.domain) return false;
        const d = r.domain;
        if (useRegex) return terms.every(t=> new RegExp(t,"i").test(d));
        const dl = d.toLowerCase();
        return terms.every(t=> dl.includes(t.toLowerCase()));
      });
    } catch { return rows; }
  }, [rows, filterText, useRegex]);

  const filteredRows = useMemo(()=>{
    const selected = Object.entries(vulnSel).filter(([,v])=>v).map(([k])=>k);
    if (selected.length===0) return domainFiltered;
    return domainFiltered.filter(r=>{
      const arr = selected.map(k=> hasVulnerability(r,k,sevWarn,sevFail));
      return vulnLogic==="all" ? arr.every(Boolean) : arr.some(Boolean);
    });
  }, [domainFiltered, vulnSel, sevWarn, sevFail, vulnLogic]);

  async function handleTxtFile(e){
    const file = e.target.files?.[0]; if(!file) return;
    if (!file.name.toLowerCase().endsWith(".txt")) { alert(".txt dosyası (her satır 1 domain) seçin."); return; }
    try {
      const text = await file.text();
      const fromFile = text.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
      const current  = input.split(/\r?\n|,|\s+/).map(s=>s.trim()).filter(Boolean);
      const merged = Array.from(new Set([...current, ...fromFile]));
      setInput(merged.join("\n"));
      setFileInfo({ name:file.name, added: merged.length - current.length });
    } catch(err){ console.error(err); alert("Dosya okunamadı."); }
    finally { e.target.value=""; }
  }

  async function runScan(){
    const domains = Array.from(new Set(input.split(/\r?\n|,|\s+/).map(s=>s.trim()).filter(Boolean)));
    if (!domains.length) return;
    setLoading(true); setRows([]); setProgress("");
    const CHUNK=100, parts=[];
    for(let i=0;i<domains.length;i+=CHUNK) parts.push(domains.slice(i,i+CHUNK));
    let done=0, all=domains.length; const allResults=[];
    try {
      for (const part of parts){
        setProgress(`Taranıyor: ${done}/${all}`);
        const r = await fetchWithTimeout(API,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domains:part})},30000);
        if(!r.ok) throw new Error(`API ${r.status}`);
        const j = await r.json();
        allResults.push(...(j.results||[]));
        done += part.length;
        setProgress(`Taranıyor: ${done}/${all}`);
      }
      setRows(allResults);
      setProgress(`Tamamlandı: ${done}/${all}`);
    } catch(e){ setProgress(`Hata: ${e.message}. API: ${API}`); }
    finally { setLoading(false); }
  }

  // Exportlar (filtreli set)
  function downloadBlob(filename, blob) { const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); }
  function exportJSON(){ if(!filteredRows.length) return; downloadBlob(`scan-results-${Date.now()}.json`, new Blob([JSON.stringify(filteredRows,null,2)],{type:"application/json"})); }
  function exportCSVSummary(){
    if(!filteredRows.length) return;
    const header = EXPORT_COLUMNS.map(c=>csvEscape(c.title)).join(",");
    const lines  = filteredRows.map(r=> EXPORT_COLUMNS.map(c=>csvEscape(c.fn(r))).join(","));
    downloadBlob(`scan-summary-${Date.now()}.csv`, new Blob([header+"\n"+lines.join("\n")],{type:"text/csv;charset=utf-8"}));
  }
  function exportCSVDetailed(){
    if(!filteredRows.length) return;
    const headerFields=["Domain","HTTP","Final URL","PASS","WARN","FAIL","INFO","HSTS","CLICK","XCTO","REFERRER","CSP","PERM","COOP","COEP","CORP","ACAO","COOKIES","SERVER","X-POWERED-BY","XSS","DETAILS_JSON","RAW_HEADERS_JSON"];
    const header = headerFields.map(csvEscape).join(",");
    const lines = filteredRows.map(r=>{
      const c = summarizeCounts(r);
      const vals=[r.domain,r.ok?r.status:"ERR",r.finalUrl||"-",c.pass,c.warn,c.fail,c.info,
        r.ok?r.checks.hsts.status:"",r.ok?r.checks.click.status:"",r.ok?r.checks.xcto.status:"",
        r.ok?(r.checks.referrerPolicy?.status||r.checks.referrer?.status):"",r.ok?r.checks.csp.status:"",
        r.ok?r.checks.perm.status:"",r.ok?r.checks.coop.status:"",r.ok?r.checks.coep.status:"",
        r.ok?r.checks.corp.status:"",r.ok?r.checks.acao.status:"",r.ok?r.checks.cookies.status:"",
        r.ok?r.checks.server.status:"",r.ok?r.checks.xpb.status:"",r.ok?r.checks.xxss.status:"",
        r.ok?JSON.stringify(r.checks._details||[]):"[]", r.ok?JSON.stringify(r.checks._rawHeaders||{}):"{}"];
      return vals.map(csvEscape).join(",");
    });
    downloadBlob(`scan-detailed-${Date.now()}.csv`, new Blob([header+"\n"+lines.join("\n")],{type:"text/csv;charset=utf-8"}));
  }
  function exportPDF(){
    if(!filteredRows.length) return;
    const win = window.open("","_blank"); if(!win) return alert("Pop-up engellendi.");
    const styles = `<style>
      body{font:14px system-ui;margin:24px}
      h1{font-size:18px;margin:0 0 12px 0}
      table{border-collapse:collapse;width:100%}
      th,td{border:1px solid #e5e7eb;padding:6px;vertical-align:top}
      th{background:#f8fafc;text-align:left}
      small{color:#64748b}
    </style>`;
    const head = ["Domain","HTTP","Final URL","PASS","WARN","FAIL","INFO","HSTS","Click","XCTO","Referrer","CSP","Perm","COOP","COEP","CORP","ACAO","Cookies","Server","X-Powered-By","XSS"].map(t=>`<th>${t}</th>`).join("");
    const body = filteredRows.map(r=>{
      const c=summarizeCounts(r); const cells=[r.domain,r.ok?r.status:"ERR",r.finalUrl||"-",c.pass,c.warn,c.fail,c.info,
        r.ok?r.checks.hsts.status:"",r.ok?r.checks.click.status:"",r.ok?r.checks.xcto.status:"",
        r.ok?(r.checks.referrerPolicy?.status||r.checks.referrer?.status):"",r.ok?r.checks.csp.status:"",
        r.ok?r.checks.perm.status:"",r.ok?r.checks.coop.status:"",r.ok?r.checks.coep.status:"",
        r.ok?r.checks.corp.status:"",r.ok?r.checks.acao.status:"",r.ok?r.checks.cookies.status:"",
        r.ok?r.checks.server.status:"",r.ok?r.checks.xpb.status:"",r.ok?r.checks.xxss.status:""];
      const tds=cells.map(v=>(v??"").toString().replace(/&/g,"&amp;").replace(/</g,"&lt;")).map(s=>`<td>${s}</td>`).join("");
      return `<tr>${tds}</tr>`;
    }).join("");
    win.document.write(`<html><head><meta charset="utf-8">${styles}<title>Scan Results</title></head><body><h1>Secure Headers Scan Results</h1><small>${new Date().toLocaleString()}</small><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table><script>window.print();</script></body></html>`);
    win.document.close();
  }

  /* ---------------- Görsel Yerleşim ---------------- */
  return (
    <div style={{ minHeight:"100vh", background:t.bg, padding:"24px 16px" }}>
      {/* Üst bar */}
      <div style={{
        maxWidth:1200, margin:"0 auto 16px auto",
        display:"flex", alignItems:"center", justifyContent:"space-between"
      }}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{
            width:34,height:34,borderRadius:8,
            background:`linear-gradient(135deg,${t.topLogoFrom},${t.topLogoTo})`,
            boxShadow:"0 6px 18px rgba(37,99,235,.35)"
          }}/>
          <h1 style={{color:t.text,fontSize:20,margin:0,fontWeight:800}}>Secure Headers Scanner</h1>
        </div>
        <div style={{display:"flex",gap:10, alignItems:"center"}}>
          <Button t={t} variant="ghost" onClick={exportCSVSummary}>CSV (Özet)</Button>
          <Button t={t} variant="ghost" onClick={exportCSVDetailed}>CSV (Detay)</Button>
          <Button t={t} variant="ghost" onClick={exportJSON}>JSON</Button>
          <Button t={t} variant="ghost" onClick={exportPDF}>PDF</Button>
          {/* Neumorfik tema anahtarı */}
          <ThemeToggle theme={theme} setTheme={setTheme} />
        </div>
      </div>

      {/* Kart: Girdi */}
<div style={{
  width: "100%",                 // 👈 %100 genişlik
  maxWidth: 1200,
  margin: "0 auto",
  background: t.cardBg,
  border: `1px solid ${t.border}`,
  borderRadius: 16,
  boxShadow: t.shadow,
  boxSizing: "border-box",       // 👈 padding dahil
  overflow: "hidden",             // 👈 kart içi taşmaları kes
  overflowX: "hidden"
}}>
  <div style={{
    padding: 18,
    borderBottom: `1px solid ${t.border}`,
    display: "flex",
    gap: 10,
    alignItems: "center",
    justifyContent: "space-between"
  }}>
    <div style={{ color: t.textMuted }}>API: <code style={{ color: t.link }}>/api</code></div>
    <div style={{ display: "flex", gap: 8 }}>
      <Button t={t} onClick={runScan} disabled={loading}>
        {loading ? "Taranıyor..." : "Taramayı Başlat"}
      </Button>
    </div>
  </div>

  <div style={{
    padding: 18,
    display: "grid",
    gap: 12,
    minWidth: 0                 // 👈 grid çocuklarının taşmasını engelle
  }}>
    <textarea
      value={input}
      onChange={e => setInput(e.target.value)}
      rows={8}
      placeholder={`example.com
github.com
wikipedia.org`}
      style={{
        display: "block",        // 👈 inline taşmayı önler
        width: "100%",
        maxWidth: "100%",
        boxSizing: "border-box", // 👈 padding dahil
        padding: 12,
        borderRadius: 12,
        background: t.inputBg,
        color: t.text,
        border: `1px solid ${t.borderSoft}`,
        outline: "none",
        resize: "vertical",      // 👈 yatay resize kapalı
        overflowWrap: "anywhere",// 👈 çok uzun kelimeleri kır
        wordBreak: "break-word"  // 👈 ekstra güvence
      }}
    />
    <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
      <label style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        border: `1px dashed ${t.borderSoft}`,
        color: t.textMuted,
        padding: "8px 12px",
        borderRadius: 12,
        cursor: "pointer",
        background: t.inputBg
      }}>
        TXT yükle
        <input type="file" accept=".txt" onChange={handleTxtFile} style={{ display: "none" }} />
      </label>
      {fileInfo.name && (
        <span style={{ color: t.textSoft }}>
          {fileInfo.name} eklendi — +{fileInfo.added} domain
        </span>
      )}
      <span style={{ color: t.textSoft }}>{progress}</span>
    </div>

          {/* Filtreler aç/kapa */}
          <div>
            <Button t={t} variant="subtle" onClick={()=>setFiltersOpen(o=>!o)}>
              {filtersOpen ? "Filtreleri Gizle" : "Filtreleri Göster"}
            </Button>
            <div style={{
              overflow:"hidden",
              transition:"max-height .35s ease, margin-top .2s ease",
              maxHeight: filtersOpen ? 900 : 0,
              marginTop: filtersOpen ? 12 : 0
            }}>
              {/* Domain filtresi */}
              <div style={{
                marginTop:12, padding:12, border:`1px solid ${t.borderSoft}`,
                borderRadius:12, background:t.inputBg
              }}>
                <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
                  <input
                    type="text"
                    value={filterText}
                    onChange={e=>setFilterText(e.target.value)}
                    placeholder="Domain filtrele (örn: gov.tr, foo|bar — regex için işaretle)"
                    style={{
                      padding:10, minWidth:320, borderRadius:10, border:`1px solid ${t.borderSoft}`,
                      background: t.cardBg, color: t.text, outline:"none"
                    }}
                  />
                  <label style={{display:"inline-flex",alignItems:"center",gap:8,color:t.textMuted}}>
                    <input type="checkbox" checked={useRegex} onChange={e=>setUseRegex(e.target.checked)}/>
                    Regex kullan
                  </label>
                  {filterText && <Button t={t} variant="ghost" onClick={()=>setFilterText("")}>Temizle</Button>}
                </div>
              </div>

              {/* Zafiyet filtresi */}
              <div style={{
                marginTop:12, padding:12, border:`1px solid ${t.borderSoft}`,
                borderRadius:12, background:t.inputBg
              }}>
                <div style={{ display:"flex", gap:16, flexWrap:"wrap", alignItems:"center", color:t.textMuted }}>
                  <strong style={{color:t.text}}>Zafiyet filtresi</strong>
                  <label style={{display:"inline-flex",alignItems:"center",gap:6}}>
                    <input type="checkbox" checked={sevFail} onChange={e=>setSevFail(e.target.checked)}/> FAIL
                  </label>
                  <label style={{display:"inline-flex",alignItems:"center",gap:6}}>
                    <input type="checkbox" checked={sevWarn} onChange={e=>setSevWarn(e.target.checked)}/> WARN
                  </label>
                  <label style={{display:"inline-flex",alignItems:"center",gap:6}}>
                    Mantık:
                    <select value={vulnLogic} onChange={e=>setVulnLogic(e.target.value)}
                      style={{ padding:6, borderRadius:8, background:t.cardBg, color:t.text, border:`1px solid ${t.borderSoft}` }}>
                      <option value="any">Herhangi biri (OR)</option>
                      <option value="all">Hepsi (AND)</option>
                    </select>
                  </label>
                  <Button t={t} variant="ghost" onClick={()=>{
                    setVulnSel({}); setSevFail(true); setSevWarn(true); setVulnLogic("any");
                  }}>Sıfırla</Button>
                </div>
                <div style={{
                  marginTop:10, display:"grid",
                  gridTemplateColumns:"repeat(auto-fill,minmax(260px,1fr))", gap:6
                }}>
                  {VULN_KEYS.map(v=>(
                    <label key={v.key} style={{ display:"inline-flex", alignItems:"center", gap:8, color:t.textMuted }}>
                      <input
                        type="checkbox"
                        checked={!!vulnSel[v.key]}
                        onChange={e=> setVulnSel(s=>({ ...s, [v.key]: e.target.checked }))}
                      />
                      {v.label}
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Sonuçlar */}
      {filteredRows.length > 0 && (
        <div style={{
          maxWidth:1200, margin:"16px auto",
          background:t.cardBg, border:`1px solid ${t.border}`,
          borderRadius:16, overflow:"hidden", boxShadow:t.shadow
        }}>
          <div style={{padding:"10px 14px", display:"flex",justifyContent:"space-between",alignItems:"center", borderBottom:`1px solid ${t.border}`, color:t.textMuted}}>
            <div>Görüntülenen: <b style={{color:t.text}}>{filteredRows.length}</b> / {rows.length}</div>
            <div style={{color:t.textSoft}}>{progress}</div>
          </div>
          <div style={{ overflow:"auto" }}>
            <table style={{ borderCollapse:"separate", borderSpacing:0, width:"100%", fontSize:14 }}>
              <thead>
                <tr style={{position:"sticky",top:0,background:t.thBg,zIndex:1}}>
                  <th style={th(t)}>Detay</th>
                  <th style={th(t)}>Domain</th>
                  <th style={th(t)}>HTTP</th>
                  <th style={th(t)}>Final URL</th>
                  <th style={th(t)}>Özet</th>
                  <th style={th(t)}>HSTS</th><th style={th(t)}>Click</th><th style={th(t)}>XCTO</th><th style={th(t)}>Referrer</th>
                  <th style={th(t)}>CSP</th><th style={th(t)}>Perm</th><th style={th(t)}>COOP</th><th style={th(t)}>COEP</th><th style={th(t)}>CORP</th>
                  <th style={th(t)}>ACAO</th><th style={th(t)}>Cookies</th><th style={th(t)}>Server</th><th style={th(t)}>X-Powered-By</th><th style={th(t)}>XSS</th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((r,i)=>{
                  const c = summarizeCounts(r);
                  return (
                    <tr key={i} style={{ background: i%2 ? t.tableAlt : "transparent" }}>
                      <td style={td(t)}>
                        {r.ok ? <Button t={t} variant="subtle" onClick={()=>setActive(r)} style={{padding:"6px 10px"}}>Gör</Button> : "-"}
                      </td>
                      <td style={{...td(t), fontWeight:700, color:t.text}}>{r.domain}</td>
                      <td style={{...td(t), fontFamily:"ui-monospace, SFMono-Regular, Menlo, monospace"}}>{r.ok ? r.status : "ERR"}</td>
                      <td style={td(t)}>
                        {r.finalUrl ? <a href={r.finalUrl} target="_blank" rel="noreferrer" style={{color:t.link}}>{r.finalUrl}</a> : "-"}
                      </td>
                      <td style={{ ...td(t), minWidth:200 }}>
                        <div title={`P:${c.pass||0} W:${c.warn||0} F:${c.fail||0} I:${c.info||0}`} style={{display:"flex",alignItems:"center",gap:10}}>
                          <MiniBar counts={c}/>
                          <span style={{fontSize:12,color:t.textSoft,whiteSpace:"nowrap"}}>P:{c.pass||0} W:{c.warn||0} F:{c.fail||0} I:{c.info||0}</span>
                        </div>
                      </td>
                      {r.ok ? (<>
                        <td style={td(t)}><Badge st={r.checks.hsts.status} title={r.checks.hsts.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.click.status} title={r.checks.click.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.xcto.status} title={r.checks.xcto.reason}/></td>
                        <td style={td(t)}><Badge st={(r.checks.referrerPolicy?.status || r.checks.referrer?.status)} title={(r.checks.referrerPolicy?.reason || r.checks.referrer?.reason)}/></td>
                        <td style={td(t)}><Badge st={r.checks.csp.status} title={r.checks.csp.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.perm.status} title={r.checks.perm.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.coop.status} title={r.checks.coop.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.coep.status} title={r.checks.coep.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.corp.status} title={r.checks.corp.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.acao.status} title={r.checks.acao.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.cookies.status} title={r.checks.cookies.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.server.status} title={r.checks.server.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.xpb.status} title={r.checks.xpb.reason}/></td>
                        <td style={td(t)}><Badge st={r.checks.xxss.status} title={r.checks.xxss.reason}/></td>
                      </>) : (
                        <td style={td(t)} colSpan={14} title={r.error}>{r.error}</td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Detay Modal */}
      {active && (
        <div style={modalBackdrop(t)} onClick={()=>setActive(null)}>
          <div style={modalCard(t)} onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
              <h3 style={{margin:0,color:t.text}}>Detay — {active.domain}</h3>
              <Button t={t} variant="ghost" onClick={()=>setActive(null)}>Kapat</Button>
            </div>
            {!active.ok ? (
              <p style={{color:"#ef4444"}}>Hata: {active.error}</p>
            ) : (
              <>
                <p style={{color:t.textSoft}}>HTTP: {active.status} • URL: {active.finalUrl}</p>
                <div style={{maxHeight:"60vh",overflow:"auto"}}>
                  <table style={{borderCollapse:"collapse",width:"100%",fontSize:14}}>
                    <thead>
                      <tr>
                        <th style={thPlain(t)}>Header</th><th style={thPlain(t)}>Durum</th><th style={thPlain(t)}>Değer</th><th style={thPlain(t)}>Açıklama</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(active.checks._details||[]).map((d,i)=>(
                        <tr key={i}>
                          <td style={tdPlain(t)}>{d.name}</td>
                          <td style={tdPlain(t)}><Badge st={d.status}/></td>
                          <td style={{...tdPlain(t),whiteSpace:"pre-wrap"}}>{d.value||"—"}</td>
                          <td style={tdPlain(t)}>{d.explain}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {active.checks._rawHeaders && (
                    <>
                      <h4 style={{color:t.text}}>Ham header’lar</h4>
                      <pre style={{
                        background:t.inputBg, border:`1px solid ${t.borderSoft}`, borderRadius:10, padding:12, color:t.textMuted, overflow:"auto"
                      }}>{JSON.stringify(active.checks._rawHeaders,null,2)}</pre>
                    </>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- Stiller ---------------- */
const th = (t) => ({
  position:"sticky", top:0, background:t.thBg, color:t.textMuted,
  borderBottom:`1px solid ${t.border}`, padding:"10px 12px", textAlign:"left"
});
const td = (t) => ({ borderTop:`1px solid ${t.borderSoft}`, padding:"10px 12px", color:t.text, verticalAlign:"top" });

const thPlain = (t) => ({ border:`1px solid ${t.borderSoft}`, padding:"8px", textAlign:"left", background:t.inputBg, color:t.textMuted });
const tdPlain = (t) => ({ border:`1px solid ${t.borderSoft}`, padding:"8px", color:t.text, verticalAlign:"top" });

const modalBackdrop = (t) => ({ position:"fixed", inset:0, background:t.overlay, display:"flex", alignItems:"center", justifyContent:"center", padding:16, zIndex:9999 });
const modalCard = (t) => ({ background:t.cardBg, border:`1px solid ${t.border}`, borderRadius:16, padding:16, maxWidth:900, width:"100%", boxShadow:t.shadow });
