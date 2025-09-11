// api.js
// Hızlı, DB'siz HTTP güvenlik başlığı tarayıcı API'sı
// CJS (require) kullanır, p-limit@3 ile uyumludur.

const express = require("express");
const cors = require("cors");
const PLimit = require("p-limit");
const pRetry = require("p-retry").default;
const { Agent, setGlobalDispatcher } = require("undici");

// --- HIZ: keep-alive agent (bağlantı reuse) ---
setGlobalDispatcher(
  new Agent({
    keepAliveTimeout: 10_000,
    keepAliveMaxTimeout: 10_000,
  })
);

const app = express();
app.use(cors()); // istersen: app.use(cors({ origin: "http://<IP>:5173" }));
app.use(express.json({ limit: "1mb" }));

// --- Yardımcılar ---
function norm(input) {
  let d = (input || "").trim();
  if (!d) return null;
  if (!/^https?:\/\//i.test(d)) d = "http://" + d;
  try {
    const u = new URL(d);
    u.pathname = "/";
    return u.toString();
  } catch {
    return null;
  }
}

const HOP_TIMEOUT_MS = 7000; // her redirect hop max 7 sn
const GLOBAL_TIMEOUT_MS = 20000; // tek domain toplam max 20 sn
const MAX_REDIRECTS = 5;

// Tek GET, manuel redirect takibi, per-hop ve global timeout
async function fetchFollowOnce(url) {
  const globalCtrl = new AbortController();
  const globalTimer = setTimeout(() => globalCtrl.abort(), GLOBAL_TIMEOUT_MS);
  try {
    let current = url;
    for (let i = 0; i < MAX_REDIRECTS; i++) {
      const signal = AbortSignal.any
        ? AbortSignal.any([globalCtrl.signal, AbortSignal.timeout(HOP_TIMEOUT_MS)])
        : globalCtrl.signal;

      const r = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal,
        headers: {
          "user-agent": "SecHeadersScanner/1.0 (+https://local)",
          accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });

      const loc = r.headers.get("location");
      if (r.status >= 300 && r.status < 400 && loc) {
        r.body?.cancel?.(); // body'yi tüketmeden kapat
        current = new URL(loc, current).toString();
        continue;
      }
      r.body?.cancel?.();
      return r;
    }
    throw new Error("Too many redirects");
  } finally {
    clearTimeout(globalTimer);
  }
}

function analyze(headers, finalUrl) {
  const h = {};
  for (const [k, v] of headers) h[k.toLowerCase()] = v;

  const out = {};
  const details = [];
  const httpsEnforced = finalUrl.startsWith("https://");
  const mk = (name, status, value, explain) => details.push({ name, status, value: value ?? "", explain });
  const badge = (ok, warn = false, reason = "") =>
    ok ? { status: "pass", reason } : warn ? { status: "warn", reason } : { status: "fail", reason };

  // --- HSTS ---
  const hsts = h["strict-transport-security"];
  if (!httpsEnforced) {
    out.hsts = badge(false, false, "HTTPS zorlaması yok");
    mk("Strict-Transport-Security", "fail", hsts, "Site http→https zorlamıyor; HSTS etkisiz.");
  } else if (!hsts) {
    out.hsts = badge(false, false, "HSTS eksik");
    mk("Strict-Transport-Security", "fail", "", "HSTS eksik; en az 180 gün max-age önerilir.");
  } else {
    const m = /max-age=(\d+)/i.exec(hsts)?.[1];
    if (!m || +m < 15552000) {
      out.hsts = badge(false, true, `HSTS zayıf: ${hsts}`);
      mk("Strict-Transport-Security", "warn", hsts, "max-age 180 günden az veya okunamadı.");
    } else {
      out.hsts = badge(true, false, `HSTS ok: ${hsts}`);
      mk("Strict-Transport-Security", "pass", hsts, "HSTS süre eşiğini karşılıyor.");
    }
  }

  // --- Clickjacking (CSP frame-ancestors > XFO) ---
  const xfo = (h["x-frame-options"] || "").toUpperCase();
  const csp = h["content-security-policy"] || "";
  const fa = csp.match(/frame-ancestors[^;]*/i)?.[0] || "";
  if (fa) {
    if (/\bframe-ancestors\b\s+(\*|'\*')/i.test(fa)) {
      out.click = badge(false,false,`Geniş: ${fa}`);
      mk("CSP frame-ancestors", "fail", fa, "Joker (*) ile framing izinli; clickjacking riski.");
    } else {
      out.click = badge(true,false,fa);
      mk("CSP frame-ancestors", "pass", fa, "Framing kısıtlanmış.");
    }
  } else if (xfo) {
    const ok = (xfo === "DENY" || xfo === "SAMEORIGIN");
    out.click = ok ? badge(true,false,`XFO ${xfo}`) : badge(false,true,`XFO zayıf: ${xfo}`);
    mk("X-Frame-Options", ok ? "pass" : "warn", xfo, ok ? "Framing kısıtlı." : "Önerilen değer değil.");
  } else {
    out.click = badge(false,false,"XFO/CSP yok");
    mk("Clickjacking", "fail", "", "Ne CSP frame-ancestors ne X-Frame-Options var.");
  }

  // --- X-Content-Type-Options ---
  const xcto = (h["x-content-type-options"] || "").toLowerCase();
  if (xcto === "nosniff") {
    out.xcto = badge(true,false,"nosniff");
    mk("X-Content-Type-Options", "pass", "nosniff", "MIME sniffing engellenmiş.");
  } else {
    out.xcto = badge(false,false,"XCTO eksik");
    mk("X-Content-Type-Options", "fail", xcto || "", "nosniff olmalı.");
  }

  // --- Referrer-Policy ---
  const rp = (h["referrer-policy"] || "").toLowerCase();
  const good = ["strict-origin-when-cross-origin","no-referrer","same-origin","strict-origin"];
  if (!rp) {
    out.referrerPolicy = badge(false,false,"eksik");
    mk("Referrer-Policy", "fail", "", "Eksik; gizlilik için gerekli.");
  } else if (good.includes(rp)) {
    out.referrerPolicy = badge(true,false,rp);
    mk("Referrer-Policy", "pass", rp, "Önerilen değer.");
  } else {
    out.referrerPolicy = badge(false,true,`değer: ${rp}`);
    mk("Referrer-Policy", "warn", rp, "Alternatif güvenli değer önerilir.");
  }

  // --- CSP (genel) ---
  if (!csp) {
    out.csp = badge(false,false,"CSP eksik");
    mk("Content-Security-Policy", "fail", "", "Eksik; kaynakları kısıtlamak için gereklidir.");
  } else if (/default-src\s+\*/i.test(csp)) {
    out.csp = badge(false,true,"CSP geniş");
    mk("Content-Security-Policy", "warn", csp, "default-src * çok geniş.");
  } else {
    out.csp = badge(true,false,"CSP var");
    mk("Content-Security-Policy", "pass", csp, "Genel olarak var; ayrıntı analizi önerilir.");
  }

  // --- Permissions-Policy ---
  if (h["permissions-policy"]) {
    out.perm = badge(true,false,"var");
    mk("Permissions-Policy", "pass", h["permissions-policy"], "Tarayıcı özellikleri kısıtlanıyor.");
  } else {
    out.perm = badge(false,false,"eksik");
    mk("Permissions-Policy", "fail", "", "Eksik; kamera/mikrofon vb. için önerilir.");
  }

  // --- COOP/COEP/CORP ---
  if (h["cross-origin-opener-policy"]) {
    out.coop = badge(true,false,h["cross-origin-opener-policy"]);
    mk("Cross-Origin-Opener-Policy", "pass", h["cross-origin-opener-policy"], "Pencere izolasyonu.");
  } else {
    out.coop = badge(false,true,"yok");
    mk("Cross-Origin-Opener-Policy", "warn", "", "Eksik; same-origin önerilir.");
  }

  if (h["cross-origin-embedder-policy"]) {
    out.coep = badge(true,false,h["cross-origin-embedder-policy"]);
    mk("Cross-Origin-Embedder-Policy", "pass", h["cross-origin-embedder-policy"], "Kaynak gömme izolasyonu.");
  } else {
    out.coep = badge(false,true,"yok");
    mk("Cross-Origin-Embedder-Policy", "warn", "", "Eksik; require-corp/credentialless önerilir.");
  }

  if (h["cross-origin-resource-policy"]) {
    out.corp = badge(true,false,h["cross-origin-resource-policy"]);
    mk("Cross-Origin-Resource-Policy", "pass", h["cross-origin-resource-policy"], "Kaynak paylaşımı kısıtlı.");
  } else {
    out.corp = badge(false,true,"yok");
    mk("Cross-Origin-Resource-Policy", "warn", "", "Eksik; same-origin/site önerilir.");
  }

  // --- CORS (ACAO) ---
  const acao = h["access-control-allow-origin"];
  if (!acao) {
    out.acao = { status: "info", reason: "yok (SOP)" };
    mk("Access-Control-Allow-Origin", "info", "", "Yok; çoğu web sayfası için normal.");
  } else if (acao.trim() === "*") {
    out.acao = badge(false,true,"*");
    mk("Access-Control-Allow-Origin", "warn", "*", "Tüm origin’lere açık; dikkatli ol.");
  } else {
    out.acao = badge(true,false,acao);
    mk("Access-Control-Allow-Origin", "pass", acao, "Belirli origin ile kısıtlı.");
  }

  // --- Cookies ---
  const sc = headers.get("set-cookie");
  if (!sc) {
    out.cookies = { status: "info", reason: "Set-Cookie yok" };
    mk("Set-Cookie", "info", "", "Yanıtta çerez set edilmemiş.");
  } else {
    const arr = String(sc).split(/\r?\n(?=.+?=)/);
    const issues = [];
    for (const ck of arr) {
      const n = ck.split(";")[0];
      if (!/;\s*Secure/i.test(ck)) issues.push(`${n}: Secure yok`);
      if (!/;\s*HttpOnly/i.test(ck)) issues.push(`${n}: HttpOnly yok`);
      if (!/;\s*SameSite\s*=\s*(Lax|Strict|None)/i.test(ck)) issues.push(`${n}: SameSite yok`);
      if (/SameSite\s*=\s*None/i.test(ck) && !/;\s*Secure/i.test(ck)) issues.push(`${n}: None→Secure zorunlu`);
    }
    if (issues.length) {
      out.cookies = badge(false,false,issues.join(" | "));
      mk("Set-Cookie", "fail", arr.join(" \\n "), issues.join(" | "));
    } else {
      out.cookies = badge(true,false,"OK");
      mk("Set-Cookie", "pass", arr.join(" \\n "), "Secure+HttpOnly+SameSite tam.");
    }
  }

  // --- Bilgi sızıntısı ---
  if (h["server"]) {
    out.server = { status: "warn", reason: `Server: ${h["server"]}` };
    mk("Server", "warn", h["server"], "Sunucu tür/sürüm sızıntısı.");
  } else {
    out.server = { status: "pass", reason: "yok" };
    mk("Server", "pass", "", "Sızıntı yok.");
  }

  if (h["x-powered-by"]) {
    out.xpb = { status: "warn", reason: `X-Powered-By: ${h["x-powered-by"]}` };
    mk("X-Powered-By", "warn", h["x-powered-by"], "Uygulama/framework sızıntısı.");
  } else {
    out.xpb = { status: "pass", reason: "yok" };
    mk("X-Powered-By", "pass", "", "Sızıntı yok.");
  }

  // --- X-XSS-Protection (ekstra) ---
  const xxss = (h["x-xss-protection"] || "").toLowerCase();
  if (!xxss) {
    out.xxss = { status: "pass", reason: "yok (modern tarayıcılar CSP kullanır)" };
    mk("X-XSS-Protection", "pass", "", "Modern tarayıcılarda deprecated; yok olması normal.");
  } else if (xxss === "0") {
    out.xxss = { status: "pass", reason: "0 (kapalı, CSP tercih edilir)" };
    mk("X-XSS-Protection", "pass", xxss, "Açıkça kapalı; CSP tercih edilir.");
  } else if (xxss.startsWith("1")) {
    out.xxss = { status: "warn", reason: `aktif ama deprecated: ${xxss}` };
    mk("X-XSS-Protection", "warn", xxss, "Artık önerilmiyor; CSP kullanın.");
  } else {
    out.xxss = { status: "fail", reason: `geçersiz değer: ${xxss}` };
    mk("X-XSS-Protection", "fail", xxss, "Geçersiz/değersiz değer.");
  }

  // Ham header’ları da döndürmek istersen:
  out._rawHeaders = h;          // <— opsiyonel, UI’da “ham başlıklar” bölümünde gösterilebilir
  out._details = details;       // <— UI için detay listesi

  return out;
}

async function scanOne(domain) {
  const base = norm(domain);
  if (!base) return { domain, ok: false, error: "Geçersiz domain/URL" };

  // 1 retry ile tekrar dene (kısa süreli hatalara karşı)
  return await pRetry(
    async () => {
      const r = await fetchFollowOnce(base);
      const finalUrl = r.url;
      const status = r.status;
      const checks = analyze(r.headers, finalUrl);
      return { domain, ok: true, status, finalUrl, checks };
    },
    {
      retries: 1,
      factor: 2,
      minTimeout: 800,
      maxTimeout: 2000,
    }
  );
}
app.get("/healthz", (req, res) => res.json({ ok: true }));
// --- API: /api/scan ---
// Body: { "domains": ["example.com", "github.com", ...] }
app.post("/api/scan", async (req, res) => {
  try {
    const { domains = [] } = req.body || {};
    if (!Array.isArray(domains) || domains.length === 0)
      return res.status(400).json({ error: "domains[] gerekli" });

    const limit = PLimit(15); // makineye göre 10–20 arası ideal
    const results = await Promise.all(
      domains.map((d) =>
        limit(() =>
          scanOne(d).catch((e) => ({
            domain: d,
            ok: false,
            error: String(e.message || e),
          }))
        )
      )
    );

    res.json({ results });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`API on http://0.0.0.0:${PORT}`)
);

