import { Activity, AlertTriangle, Award, GitCompare } from "lucide-react";
import { Locale, TRANSLATIONS } from "../i18n/translations";
import { ScanDiff, ScanResult } from "../types/scan";

interface SummaryCardsProps {
  locale: Locale;
  rows: ScanResult[];
  diff: ScanDiff | null;
}

export function SummaryCards({ locale, rows, diff }: SummaryCardsProps) {
  if (!rows.length) return null;
  const t = TRANSLATIONS[locale];

  const okRows = rows.filter((r) => r.ok);
  const scores = okRows.map((r) => r.score ?? 0);
  const avg = scores.length
    ? (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1)
    : "—";
  const totalFails = okRows.reduce((acc, r) => acc + r.summary.fail, 0);

  return (
    <div className="max-w-7xl mx-auto mb-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 shadow-sm">
        <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
          <span>{t.totalScanned}</span>
          <Activity className="w-4 h-4 text-blue-500" />
        </div>
        <div className="mt-2 text-2xl font-extrabold text-slate-900 dark:text-white">
          {rows.length}
          <span className="ml-2 text-xs font-normal text-slate-500">
            ({okRows.length} OK / {rows.length - okRows.length} ERR)
          </span>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 shadow-sm">
        <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
          <span>{t.avgScore}</span>
          <Award className="w-4 h-4 text-emerald-500" />
        </div>
        <div className="mt-2 text-2xl font-extrabold text-slate-900 dark:text-white">
          {avg}
          {avg !== "—" && <span className="text-sm font-medium text-slate-400"> / 100</span>}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 shadow-sm">
        <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
          <span>{t.criticalFails}</span>
          <AlertTriangle className="w-4 h-4 text-rose-500" />
        </div>
        <div className="mt-2 text-2xl font-extrabold text-rose-600 dark:text-rose-400">
          {totalFails}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 shadow-sm">
        <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
          <span>{t.diffSummary}</span>
          <GitCompare className="w-4 h-4 text-indigo-500" />
        </div>
        {diff ? (
          <div className="mt-2 flex flex-wrap gap-2 text-xs font-semibold">
            <span className="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300">
              ▲ {diff.improved} {t.improved}
            </span>
            <span className="px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-300">
              ▼ {diff.regressed} {t.regressed}
            </span>
            {diff.added > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-300">
                +{diff.added} {t.newTarget}
              </span>
            )}
          </div>
        ) : (
          <div className="mt-2 text-sm text-slate-400">—</div>
        )}
      </div>
    </div>
  );
}
