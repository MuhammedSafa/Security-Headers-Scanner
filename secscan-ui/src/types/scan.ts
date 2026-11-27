export type CheckStatus = "pass" | "warn" | "fail" | "info";

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export type DiffTrend = "improved" | "regressed" | "unchanged" | "new" | "removed";

export interface RedirectHop {
  url: string;
  status: number;
}

export interface HeaderCheck {
  key: string;
  header: string;
  status: CheckStatus;
  code: string;
  params?: Record<string, string>;
  value: string;
  reason: string;
  issues?: string[];
}

export interface RemediationSnippet {
  title: string;
  nginx: string;
  apache: string;
  express: string;
  cloudflare: string;
}

export interface CheckSummary {
  pass: number;
  warn: number;
  fail: number;
  info: number;
}

export interface ScanResult {
  domain: string;
  ok: boolean;
  error?: string;
  errorCode?: string;
  status?: number;
  finalUrl?: string;
  httpsEnforced: boolean;
  httpRedirectedToHttps: boolean;
  redirectChain: RedirectHop[];
  durationMs: number;
  score?: number;
  grade?: Grade;
  summary: CheckSummary;
  checks: Record<string, HeaderCheck>;
  rawHeaders: Record<string, string[]>;
  remediations?: Record<string, RemediationSnippet>;
}

export interface ScanSnapshot {
  version: number;
  timestamp: string;
  total: number;
  succeeded: number;
  failed: number;
  averageScore?: number;
  results: ScanResult[];
}

export interface HeaderDiff {
  key: string;
  header: string;
  before: CheckStatus;
  after: CheckStatus;
  trend: DiffTrend;
}

export interface DomainDiff {
  domain: string;
  trend: DiffTrend;
  previousScore?: number;
  currentScore?: number;
  scoreDelta?: number;
  previousGrade?: Grade;
  currentGrade?: Grade;
  headerChanges?: HeaderDiff[];
}

export interface ScanDiff {
  previousTimestamp: string;
  currentTimestamp: string;
  improved: number;
  regressed: number;
  unchanged: number;
  added: number;
  removed: number;
  domains: Record<string, DomainDiff>;
}

export interface CheckColumn {
  key: string;
  shortLabel: string;
  fullLabel: string;
}

export const CHECK_COLUMNS: CheckColumn[] = [
  { key: "hsts", shortLabel: "HSTS", fullLabel: "Strict-Transport-Security" },
  { key: "csp", shortLabel: "CSP", fullLabel: "Content-Security-Policy" },
  { key: "click", shortLabel: "Click", fullLabel: "Clickjacking (frame-ancestors / XFO)" },
  { key: "xcto", shortLabel: "XCTO", fullLabel: "X-Content-Type-Options" },
  { key: "referrerPolicy", shortLabel: "Referrer", fullLabel: "Referrer-Policy" },
  { key: "perm", shortLabel: "Perm", fullLabel: "Permissions-Policy" },
  { key: "cookies", shortLabel: "Cookies", fullLabel: "Set-Cookie (Secure/HttpOnly/SameSite)" },
  { key: "coop", shortLabel: "COOP", fullLabel: "Cross-Origin-Opener-Policy" },
  { key: "coep", shortLabel: "COEP", fullLabel: "Cross-Origin-Embedder-Policy" },
  { key: "corp", shortLabel: "CORP", fullLabel: "Cross-Origin-Resource-Policy" },
  { key: "acao", shortLabel: "CORS", fullLabel: "Access-Control-Allow-Origin" },
  { key: "server", shortLabel: "Server", fullLabel: "Server Banner" },
  { key: "xpb", shortLabel: "X-PB", fullLabel: "X-Powered-By" },
  { key: "infoLeak", shortLabel: "Tech", fullLabel: "Tech Disclosure (AspNet/Via)" },
  { key: "xxss", shortLabel: "XSS", fullLabel: "X-XSS-Protection" },
];
