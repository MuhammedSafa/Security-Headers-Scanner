import { Filter, X } from "lucide-react";
import { Locale, TRANSLATIONS } from "../i18n/translations";
import { CHECK_COLUMNS } from "../types/scan";

interface FilterPanelProps {
  locale: Locale;
  open: boolean;
  setOpen: (v: boolean) => void;
  filterText: string;
  setFilterText: (v: string) => void;
  useRegex: boolean;
  setUseRegex: (v: boolean) => void;
  regexError: string | null;
  vulnSel: Record<string, boolean>;
  setVulnSel: React.Dispatch<React.SetStateAction<Record<string, boolean>>>;
  sevFail: boolean;
  setSevFail: (v: boolean) => void;
  sevWarn: boolean;
  setSevWarn: (v: boolean) => void;
  vulnLogic: "any" | "all";
  setVulnLogic: (v: "any" | "all") => void;
  onlyChanged: boolean;
  setOnlyChanged: (v: boolean) => void;
  hasDiff: boolean;
}

export function FilterPanel({
  locale,
  open,
  setOpen,
  filterText,
  setFilterText,
  useRegex,
  setUseRegex,
  regexError,
  vulnSel,
  setVulnSel,
  sevFail,
  setSevFail,
  sevWarn,
  setSevWarn,
  vulnLogic,
  setVulnLogic,
  onlyChanged,
  setOnlyChanged,
  hasDiff,
}: FilterPanelProps) {
  const t = TRANSLATIONS[locale];

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
      >
        <Filter className="w-3.5 h-3.5" />
        {open ? t.filtersHide : t.filtersShow}
      </button>

      {open && (
        <div className="mt-3 space-y-3">
          <div className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60">
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="text"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                placeholder={t.domainFilterPlaceholder}
                className="flex-1 min-w-[260px] px-3 py-2 rounded-lg text-sm border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useRegex}
                  onChange={(e) => setUseRegex(e.target.checked)}
                  className="rounded border-slate-300"
                />
                {t.useRegex}
              </label>
              {hasDiff && (
                <label className="inline-flex items-center gap-2 text-xs font-medium text-indigo-700 dark:text-indigo-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={onlyChanged}
                    onChange={(e) => setOnlyChanged(e.target.checked)}
                    className="rounded border-slate-300"
                  />
                  {t.onlyChanged}
                </label>
              )}
              {filterText && (
                <button
                  type="button"
                  onClick={() => setFilterText("")}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300"
                >
                  <X className="w-3.5 h-3.5" />
                  {t.clear}
                </button>
              )}
            </div>
            {regexError && (
              <p className="mt-2 text-xs font-medium text-rose-600 dark:text-rose-400">
                {t.invalidRegex}: {regexError}
              </p>
            )}
          </div>

          <div className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60">
            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-700 dark:text-slate-300">
              <strong className="text-slate-900 dark:text-white">{t.vulnFilterTitle}</strong>
              <label className="inline-flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sevFail}
                  onChange={(e) => setSevFail(e.target.checked)}
                />
                FAIL
              </label>
              <label className="inline-flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sevWarn}
                  onChange={(e) => setSevWarn(e.target.checked)}
                />
                WARN
              </label>
              <label className="inline-flex items-center gap-1.5">
                {t.logicLabel}
                <select
                  value={vulnLogic}
                  onChange={(e) => setVulnLogic(e.target.value as "any" | "all")}
                  className="px-2 py-1 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
                >
                  <option value="any">{t.logicAny}</option>
                  <option value="all">{t.logicAll}</option>
                </select>
              </label>
              <button
                type="button"
                onClick={() => {
                  setVulnSel({});
                  setSevFail(true);
                  setSevWarn(true);
                  setVulnLogic("any");
                  setOnlyChanged(false);
                }}
                className="px-2.5 py-1 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200"
              >
                {t.reset}
              </button>
            </div>

            <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {CHECK_COLUMNS.map((col) => (
                <label
                  key={col.key}
                  className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={!!vulnSel[col.key]}
                    onChange={(e) =>
                      setVulnSel((prev) => ({ ...prev, [col.key]: e.target.checked }))
                    }
                  />
                  <span>{col.fullLabel}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
