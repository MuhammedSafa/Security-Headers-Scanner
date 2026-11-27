import { ArrowUpDown, ChevronLeft, ChevronRight, ExternalLink } from "lucide-react";
import { useMemo, useState } from "react";
import { Locale, TRANSLATIONS, translateCheckReason } from "../i18n/translations";
import { CHECK_COLUMNS, ScanDiff, ScanResult } from "../types/scan";
import { isSafeHttpUrl } from "../utils/export";
import { SortDir, SortKey } from "../utils/filters";
import { DiffBadge, GradeBadge, MiniBar, StatusBadge } from "./Badges";

interface ResultsTableProps {
  locale: Locale;
  rows: ScanResult[];
  totalRows: number;
  diff: ScanDiff | null;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (key: SortKey) => void;
  onInspect: (row: ScanResult) => void;
}

export function ResultsTable({
  locale,
  rows,
  totalRows,
  diff,
  sortKey,
  sortDir,
  onSort,
  onInspect,
}: ResultsTableProps) {
  const t = TRANSLATIONS[locale];
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(page, totalPages);

  const pageRows = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, safePage, pageSize]);

  const SortButton = ({ k, label }: { k: SortKey; label: string }) => (
    <button
      type="button"
      onClick={() => onSort(k)}
      className="inline-flex items-center gap-1 font-semibold hover:text-blue-600 dark:hover:text-blue-400"
    >
      {label}
      <ArrowUpDown
        className={`w-3 h-3 ${
          sortKey === k ? "text-blue-600 dark:text-blue-400" : "opacity-40"
        }`}
        aria-label={sortKey === k ? sortDir : "unsorted"}
      />
    </button>
  );

  return (
    <section className="max-w-7xl mx-auto rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600 dark:text-slate-300">
        <div>
          {t.showing}: <strong className="text-slate-900 dark:text-white">{rows.length}</strong> /{" "}
          {totalRows}
        </div>
        <div className="flex items-center gap-3">
          <label className="inline-flex items-center gap-1.5">
            {t.perPage}
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="px-2 py-1 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            >
              {[25, 50, 100, 250].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <div className="inline-flex items-center gap-1.5">
            <button
              type="button"
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="p-1 rounded border border-slate-200 dark:border-slate-700 disabled:opacity-40"
              aria-label={t.prev}
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <span>
              {t.page} {safePage} / {totalPages}
            </span>
            <button
              type="button"
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="p-1 rounded border border-slate-200 dark:border-slate-700 disabled:opacity-40"
              aria-label={t.next}
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-50 dark:bg-slate-950/90 border-b border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300">
              <th className="px-3 py-2.5 sticky left-0 bg-slate-50 dark:bg-slate-950 z-10">
                {t.colDetail}
              </th>
              <th className="px-3 py-2.5">
                <SortButton k="domain" label={t.colDomain} />
              </th>
              <th className="px-3 py-2.5">
                <SortButton k="score" label={t.colScore} />
              </th>
              <th className="px-3 py-2.5">{t.colGrade}</th>
              {diff && <th className="px-3 py-2.5">{t.colDiff}</th>}
              <th className="px-3 py-2.5">
                <SortButton k="status" label={t.colHttp} />
              </th>
              <th className="px-3 py-2.5">{t.colFinalUrl}</th>
              <th className="px-3 py-2.5">
                <SortButton k="fail" label={t.colSummary} />
              </th>
              {CHECK_COLUMNS.map((c) => (
                <th key={c.key} className="px-2.5 py-2.5 whitespace-nowrap" title={c.fullLabel}>
                  {c.shortLabel}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
            {pageRows.map((r) => {
              const domainDiff = diff?.domains[r.domain];
              return (
                <tr
                  key={r.domain}
                  className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors"
                >
                  <td className="px-3 py-2.5 sticky left-0 bg-white dark:bg-slate-900">
                    <button
                      type="button"
                      onClick={() => onInspect(r)}
                      className="px-2.5 py-1 rounded-md font-semibold border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-blue-50 dark:hover:bg-blue-950/50 hover:text-blue-700 dark:hover:text-blue-300"
                    >
                      {t.viewBtn}
                    </button>
                  </td>
                  <td className="px-3 py-2.5 font-bold text-slate-900 dark:text-white whitespace-nowrap">
                    {r.domain}
                  </td>
                  <td className="px-3 py-2.5 font-mono font-bold text-slate-700 dark:text-slate-200">
                    {r.score !== undefined ? r.score : "—"}
                  </td>
                  <td className="px-3 py-2.5">
                    <GradeBadge grade={r.grade} />
                  </td>
                  {diff && (
                    <td className="px-3 py-2.5 whitespace-nowrap">
                      <DiffBadge diff={domainDiff} />
                    </td>
                  )}
                  <td className="px-3 py-2.5 font-mono text-slate-600 dark:text-slate-300">
                    {r.ok ? r.status : "ERR"}
                  </td>
                  <td className="px-3 py-2.5 max-w-[240px] truncate">
                    {r.finalUrl && isSafeHttpUrl(r.finalUrl) ? (
                      <a
                        href={r.finalUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 hover:underline"
                        title={r.finalUrl}
                      >
                        <span className="truncate max-w-[200px]">{r.finalUrl}</span>
                        <ExternalLink className="w-3 h-3 shrink-0" />
                      </a>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    {r.ok ? (
                      <div className="flex items-center gap-2">
                        <MiniBar counts={r.summary} />
                        <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                          {r.summary.pass}/{r.summary.warn}/{r.summary.fail}/{r.summary.info}
                        </span>
                      </div>
                    ) : (
                      <span className="text-rose-600 dark:text-rose-400 font-medium">
                        {r.errorCode
                          ? translateCheckReason(locale, r.errorCode, r.error ?? "Error")
                          : r.error}
                      </span>
                    )}
                  </td>
                  {r.ok ? (
                    CHECK_COLUMNS.map((c) => {
                      const chk = r.checks[c.key];
                      if (!chk) {
                        return (
                          <td key={c.key} className="px-2.5 py-2.5 text-slate-400">
                            —
                          </td>
                        );
                      }
                      const tooltip = translateCheckReason(locale, chk.code, chk.reason);
                      return (
                        <td key={c.key} className="px-2.5 py-2.5">
                          <StatusBadge status={chk.status} title={tooltip} />
                        </td>
                      );
                    })
                  ) : (
                    <td
                      colSpan={CHECK_COLUMNS.length}
                      className="px-3 py-2.5 text-rose-600 dark:text-rose-400"
                    >
                      {r.error}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
