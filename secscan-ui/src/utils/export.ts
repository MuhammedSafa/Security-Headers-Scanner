import yaml from "js-yaml";
import { CHECK_COLUMNS, ScanResult, ScanSnapshot } from "../types/scan";

/**
 * Escapes CSV values and neutralizes CSV/Excel Formula Injection payloads
 * starting with =, +, -, @, tab, or carriage return.
 */
export function csvEscape(value: unknown): string {
  let s = (value ?? "").toString();
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function escapeHtml(value: unknown): string {
  return (value ?? "")
    .toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function isSafeHttpUrl(url?: string): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function exportJSON(rows: ScanResult[]): void {
  if (!rows.length) return;
  downloadBlob(
    `scan-results-${Date.now()}.json`,
    new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" })
  );
}

export function exportYAML(rows: ScanResult[], snapshot?: ScanSnapshot | null): void {
  if (!rows.length) return;
  const payload: ScanSnapshot = snapshot ?? {
    version: 1,
    timestamp: new Date().toISOString(),
    total: rows.length,
    succeeded: rows.filter((r) => r.ok).length,
    failed: rows.filter((r) => !r.ok).length,
    results: rows,
  };
  const dumped = yaml.dump(payload, { lineWidth: 120, noRefs: true });
  downloadBlob(
    `scan-snapshot-${Date.now()}.yaml`,
    new Blob([dumped], { type: "application/yaml;charset=utf-8" })
  );
}

export function exportCSVSummary(rows: ScanResult[]): void {
  if (!rows.length) return;
  const headers = [
    "Domain",
    "HTTP",
    "Score",
    "Grade",
    "Final URL",
    ...CHECK_COLUMNS.map((c) => c.shortLabel),
  ];
  const lines = rows.map((r) => {
    const cells = [
      r.domain,
      r.ok ? r.status ?? "" : "ERR",
      r.score ?? "",
      r.grade ?? "",
      r.finalUrl ?? "-",
      ...CHECK_COLUMNS.map((c) => (r.ok ? r.checks[c.key]?.status ?? "" : "")),
    ];
    return cells.map(csvEscape).join(",");
  });
  downloadBlob(
    `scan-summary-${Date.now()}.csv`,
    new Blob([headers.map(csvEscape).join(",") + "\n" + lines.join("\n")], {
      type: "text/csv;charset=utf-8",
    })
  );
}

export function exportCSVDetailed(rows: ScanResult[]): void {
  if (!rows.length) return;
  const headers = [
    "Domain",
    "HTTP",
    "Score",
    "Grade",
    "Final URL",
    "PASS",
    "WARN",
    "FAIL",
    "INFO",
    ...CHECK_COLUMNS.map((c) => c.shortLabel),
    "CHECKS_JSON",
    "RAW_HEADERS_JSON",
  ];
  const lines = rows.map((r) => {
    const cells = [
      r.domain,
      r.ok ? r.status ?? "" : "ERR",
      r.score ?? "",
      r.grade ?? "",
      r.finalUrl ?? "-",
      r.summary.pass,
      r.summary.warn,
      r.summary.fail,
      r.summary.info,
      ...CHECK_COLUMNS.map((c) => (r.ok ? r.checks[c.key]?.status ?? "" : "")),
      r.ok ? JSON.stringify(r.checks) : "{}",
      r.ok ? JSON.stringify(r.rawHeaders) : "{}",
    ];
    return cells.map(csvEscape).join(",");
  });
  downloadBlob(
    `scan-detailed-${Date.now()}.csv`,
    new Blob([headers.map(csvEscape).join(",") + "\n" + lines.join("\n")], {
      type: "text/csv;charset=utf-8",
    })
  );
}

export function exportPDF(rows: ScanResult[]): void {
  if (!rows.length) return;
  const win = window.open("", "_blank", "noopener,noreferrer");
  if (!win) {
    alert("Pop-up blocked.");
    return;
  }

  const headCells = [
    "Domain",
    "HTTP",
    "Score",
    "Grade",
    "Final URL",
    "P/W/F/I",
    ...CHECK_COLUMNS.map((c) => c.shortLabel),
  ]
    .map((h) => `<th>${escapeHtml(h)}</th>`)
    .join("");

  const bodyRows = rows
    .map((r) => {
      const pwfi = `${r.summary.pass}/${r.summary.warn}/${r.summary.fail}/${r.summary.info}`;
      const cells = [
        r.domain,
        r.ok ? r.status ?? "" : "ERR",
        r.score ?? "-",
        r.grade ?? "-",
        r.finalUrl ?? "-",
        pwfi,
        ...CHECK_COLUMNS.map((c) => (r.ok ? r.checks[c.key]?.status ?? "" : "")),
      ];
      return `<tr>${cells.map((v) => `<td>${escapeHtml(v)}</td>`).join("")}</tr>`;
    })
    .join("");

  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Secure Headers Scan Report</title>
  <style>
    body { font: 12px system-ui, sans-serif; margin: 20px; color: #0f172a; }
    h1 { font-size: 18px; margin: 0 0 6px 0; }
    small { color: #64748b; display: block; margin-bottom: 14px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #cbd5e1; padding: 5px 6px; text-align: left; vertical-align: top; }
    th { background: #f1f5f9; font-weight: 700; }
  </style>
</head>
<body>
  <h1>Secure Headers Scan Results</h1>
  <small>${escapeHtml(new Date().toLocaleString())}</small>
  <table>
    <thead><tr>${headCells}</tr></thead>
    <tbody>${bodyRows}</tbody>
  </table>
</body>
</html>`;

  win.document.open();
  win.document.write(html);
  win.document.close();
  win.focus();
  win.print();
}
