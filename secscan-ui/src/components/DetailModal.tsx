import { ArrowRight, Check, Copy, X } from "lucide-react";
import { useState } from "react";
import { Locale, TRANSLATIONS, translateCheckReason } from "../i18n/translations";
import { DomainDiff, ScanResult } from "../types/scan";
import { DiffBadge, GradeBadge, StatusBadge } from "./Badges";

interface DetailModalProps {
  locale: Locale;
  result: ScanResult;
  diff?: DomainDiff;
  onClose: () => void;
}

type Platform = "nginx" | "apache" | "express" | "cloudflare";

export function DetailModal({ locale, result, diff, onClose }: DetailModalProps) {
  const t = TRANSLATIONS[locale];
  const [platform, setPlatform] = useState<Platform>("nginx");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const remediations = Object.entries(result.remediations ?? {});

  const copySnippet = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1600);
    } catch {
      // clipboard unavailable
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-4xl max-h-[88vh] flex flex-col rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <GradeBadge grade={result.grade} />
            <div className="min-w-0">
              <h2 className="text-base font-extrabold text-slate-900 dark:text-white truncate">
                {t.detailTitle} — {result.domain}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                HTTP {result.status ?? "ERR"} • {result.score ?? "—"}/100 • {t.durationMs}:{" "}
                {result.durationMs}ms • {result.httpsEnforced ? t.httpsYes : t.httpsNo}
              </p>
            </div>
            {diff && <DiffBadge diff={diff} />}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-500 hover:text-slate-900 dark:hover:text-white"
            aria-label={t.closeBtn}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto space-y-6 text-sm">
          {!result.ok ? (
            <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300">
              {result.errorCode
                ? translateCheckReason(locale, result.errorCode, result.error ?? "Error")
                : result.error}
              {result.error && (
                <div className="mt-1 text-xs font-mono opacity-80">{result.error}</div>
              )}
            </div>
          ) : (
            <>
              {/* Redirect chain */}
              {result.redirectChain.length > 0 && (
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                    {t.redirectChain}
                  </h3>
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-200 dark:border-slate-800">
                    {result.redirectChain.map((hop, idx) => (
                      <span key={idx} className="inline-flex items-center gap-1.5">
                        <span className="px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-300 font-bold">
                          {hop.status}
                        </span>
                        <span className="text-slate-700 dark:text-slate-300 break-all">
                          {hop.url}
                        </span>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                      </span>
                    ))}
                    <span className="px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/40 text-emerald-800 dark:text-emerald-300 font-bold">
                      {result.status}
                    </span>
                    <span className="text-slate-900 dark:text-white font-semibold break-all">
                      {result.finalUrl}
                    </span>
                  </div>
                </div>
              )}

              {/* Diff vs previous YAML */}
              {diff && diff.headerChanges && diff.headerChanges.length > 0 && (
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                    {t.diffChanges}
                  </h3>
                  <div className="grid gap-2">
                    {diff.headerChanges.map((hc) => (
                      <div
                        key={hc.key}
                        className="flex items-center justify-between px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs"
                      >
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          {hc.header}
                        </span>
                        <div className="flex items-center gap-2">
                          <StatusBadge status={hc.before} />
                          <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                          <StatusBadge status={hc.after} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Header checks table */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                  {t.headerChecks}
                </h3>
                <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                        <th className="p-2.5">{t.colHeader}</th>
                        <th className="p-2.5">{t.colStatus}</th>
                        <th className="p-2.5">{t.colValue}</th>
                        <th className="p-2.5">{t.colExplanation}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {Object.values(result.checks).map((chk) => (
                        <tr key={chk.key}>
                          <td className="p-2.5 font-semibold text-slate-900 dark:text-white whitespace-nowrap">
                            {chk.header}
                          </td>
                          <td className="p-2.5">
                            <StatusBadge status={chk.status} />
                          </td>
                          <td className="p-2.5 font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all max-w-[260px] whitespace-pre-wrap">
                            {chk.value || "—"}
                          </td>
                          <td className="p-2.5 text-slate-600 dark:text-slate-300">
                            <div>{translateCheckReason(locale, chk.code, chk.reason)}</div>
                            {chk.issues && chk.issues.length > 0 && (
                              <div className="mt-1 flex flex-wrap gap-1">
                                {chk.issues.map((issue, idx) => (
                                  <span
                                    key={idx}
                                    className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-[10px] font-mono text-slate-600 dark:text-slate-300"
                                  >
                                    {issue}
                                  </span>
                                ))}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Remediation snippets */}
              {remediations.length > 0 && (
                <div>
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      {t.remediations}
                    </h3>
                    <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-700 p-0.5 bg-slate-100 dark:bg-slate-950 text-xs">
                      {(["nginx", "apache", "express", "cloudflare"] as Platform[]).map((p) => (
                        <button
                          key={p}
                          type="button"
                          onClick={() => setPlatform(p)}
                          className={`px-2.5 py-1 rounded-md font-semibold capitalize transition-colors ${
                            platform === p
                              ? "bg-white dark:bg-slate-800 text-blue-600 dark:text-blue-400 shadow-sm"
                              : "text-slate-600 dark:text-slate-400"
                          }`}
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-2.5">
                    {remediations.map(([key, rem]) => {
                      const code = rem[platform];
                      return (
                        <div
                          key={key}
                          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 overflow-hidden"
                        >
                          <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
                            <span className="font-semibold text-slate-800 dark:text-slate-200">
                              {rem.title}
                            </span>
                            <button
                              type="button"
                              onClick={() => copySnippet(key, code)}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:text-blue-600"
                            >
                              {copiedKey === key ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-500" />
                                  {t.copied}
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  {t.copy}
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3 text-xs font-mono text-slate-800 dark:text-slate-200 overflow-x-auto whitespace-pre-wrap">
                            {code}
                          </pre>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Raw headers */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                  {t.rawHeaders}
                </h3>
                <pre className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs font-mono text-slate-700 dark:text-slate-300 overflow-x-auto">
                  {JSON.stringify(result.rawHeaders, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
