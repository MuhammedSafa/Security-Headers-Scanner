import { FileUp, GitCompare, History, Play, Square } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { DetailModal } from "./components/DetailModal";
import { FilterPanel } from "./components/FilterPanel";
import { HeaderBar } from "./components/HeaderBar";
import { ResultsTable } from "./components/ResultsTable";
import { SummaryCards } from "./components/SummaryCards";
import { useScanner } from "./hooks/useScanner";
import { useTheme } from "./hooks/useTheme";
import { Locale, TRANSLATIONS } from "./i18n/translations";
import { ScanResult } from "./types/scan";
import {
  exportCSVDetailed,
  exportCSVSummary,
  exportJSON,
  exportPDF,
  exportYAML,
} from "./utils/export";
import { filterResults, SortDir, SortKey, sortResults } from "./utils/filters";

export default function App() {
  const { theme, toggle: toggleTheme } = useTheme();
  const [locale, setLocale] = useState<Locale>(() => {
    const saved = localStorage.getItem("secscan-locale");
    return saved === "en" || saved === "tr" ? saved : "tr";
  });

  useEffect(() => {
    localStorage.setItem("secscan-locale", locale);
    document.documentElement.lang = locale;
  }, [locale]);

  const t = TRANSLATIONS[locale];

  const [input, setInput] = useState("example.com\ngithub.com\nwikipedia.org");
  const [notice, setNotice] = useState<string>("");
  const [active, setActive] = useState<ScanResult | null>(null);

  // Filters & sorting
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [filterText, setFilterText] = useState("");
  const [useRegex, setUseRegex] = useState(false);
  const [vulnSel, setVulnSel] = useState<Record<string, boolean>>({});
  const [sevFail, setSevFail] = useState(true);
  const [sevWarn, setSevWarn] = useState(true);
  const [vulnLogic, setVulnLogic] = useState<"any" | "all">("any");
  const [onlyChanged, setOnlyChanged] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const {
    loading,
    done,
    total,
    statusMessage,
    error,
    rows,
    snapshot,
    diff,
    runScan,
    cancelScan,
    loadPreviousScan,
    compareWithYaml,
  } = useScanner();

  const { rows: filteredRows, regexError } = useMemo(
    () =>
      filterResults(rows, {
        filterText,
        useRegex,
        vulnSel,
        sevFail,
        sevWarn,
        vulnLogic,
        onlyChanged,
        diff,
      }),
    [rows, filterText, useRegex, vulnSel, sevFail, sevWarn, vulnLogic, onlyChanged, diff]
  );

  const sortedRows = useMemo(
    () => sortResults(filteredRows, sortKey, sortDir),
    [filteredRows, sortKey, sortDir]
  );

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "domain" ? "asc" : "desc");
    }
  };

  const handleStart = () => {
    setNotice("");
    const domains = Array.from(
      new Set(
        input
          .split(/\r?\n|,|\s+/)
          .map((s) => s.trim())
          .filter(Boolean)
      )
    );
    if (!domains.length) return;
    void runScan(domains);
  };

  const handleTxtUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const fromFile = text
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s && !s.startsWith("#"));
      const current = input
        .split(/\r?\n|,|\s+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const merged = Array.from(new Set([...current, ...fromFile]));
      setInput(merged.join("\n"));
      setNotice(`${file.name} ${t.addedFromFile} (+${merged.length - current.length} ${t.newDomains})`);
    } finally {
      e.target.value = "";
    }
  };

  const handleYamlCompareUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const yamlText = await file.text();
      const ok = await compareWithYaml(yamlText);
      if (ok) {
        setNotice(`${file.name}: ${t.diffComputed}`);
      }
    } finally {
      e.target.value = "";
    }
  };

  const handleLoadPrevious = async () => {
    const loaded = await loadPreviousScan();
    setNotice(loaded ? t.previousLoaded : t.noPreviousFound);
  };

  const progressPct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 px-4 py-6 transition-colors">
      <HeaderBar
        locale={locale}
        setLocale={setLocale}
        theme={theme}
        toggleTheme={toggleTheme}
        hasResults={sortedRows.length > 0}
        onExportCsvSummary={() => exportCSVSummary(sortedRows)}
        onExportCsvDetailed={() => exportCSVDetailed(sortedRows)}
        onExportJson={() => exportJSON(sortedRows)}
        onExportYaml={() => exportYAML(sortedRows, snapshot)}
        onExportPdf={() => exportPDF(sortedRows)}
      />

      {/* Input Card */}
      <section className="max-w-7xl mx-auto mb-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {t.domainsHelp}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleLoadPrevious}
              disabled={loading}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 disabled:opacity-50"
            >
              <History className="w-3.5 h-3.5" />
              {t.loadPrevious}
            </button>

            {loading ? (
              <button
                type="button"
                onClick={cancelScan}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold bg-rose-600 hover:bg-rose-700 text-white shadow-sm"
              >
                <Square className="w-3.5 h-3.5" />
                {t.stopScan}
              </button>
            ) : (
              <button
                type="button"
                onClick={handleStart}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold bg-blue-600 hover:bg-blue-700 text-white shadow-sm shadow-blue-600/25"
              >
                <Play className="w-3.5 h-3.5" />
                {t.startScan}
              </button>
            )}
          </div>
        </div>

        <div className="p-5 space-y-4">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={6}
            placeholder={t.domainsPlaceholder}
            className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 p-3 text-sm font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
          />

          <div className="flex flex-wrap items-center gap-3 text-xs">
            <label className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-700 dark:text-slate-300 hover:border-blue-500 cursor-pointer font-medium">
              <FileUp className="w-3.5 h-3.5" />
              {t.uploadTxt}
              <input
                type="file"
                accept=".txt"
                onChange={handleTxtUpload}
                className="hidden"
              />
            </label>

            {rows.length > 0 && (
              <label className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-dashed border-indigo-300 dark:border-indigo-700 bg-indigo-50/50 dark:bg-indigo-950/30 text-indigo-700 dark:text-indigo-300 hover:border-indigo-500 cursor-pointer font-medium">
                <GitCompare className="w-3.5 h-3.5" />
                {t.compareYaml}
                <input
                  type="file"
                  accept=".yaml,.yml"
                  onChange={handleYamlCompareUpload}
                  className="hidden"
                />
              </label>
            )}

            {notice && (
              <span className="text-slate-600 dark:text-slate-300 font-medium">{notice}</span>
            )}

            {statusMessage && (
              <span className="font-mono text-slate-500 dark:text-slate-400">
                {statusMessage === "scanning"
                  ? `${t.scanning}: ${done}/${total} (${progressPct}%)`
                  : statusMessage === "completed"
                  ? `${t.completed}: ${done}/${total}`
                  : statusMessage === "cancelled"
                  ? `${t.cancelled}: ${done}/${total}`
                  : statusMessage}
              </span>
            )}
          </div>

          {loading && (
            <div className="w-full h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-600 to-emerald-500 transition-all duration-200"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          )}

          {error && (
            <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-800 text-xs text-rose-700 dark:text-rose-300 font-medium">
              {error}
            </div>
          )}

          <FilterPanel
            locale={locale}
            open={filtersOpen}
            setOpen={setFiltersOpen}
            filterText={filterText}
            setFilterText={setFilterText}
            useRegex={useRegex}
            setUseRegex={setUseRegex}
            regexError={regexError}
            vulnSel={vulnSel}
            setVulnSel={setVulnSel}
            sevFail={sevFail}
            setSevFail={setSevFail}
            sevWarn={sevWarn}
            setSevWarn={setSevWarn}
            vulnLogic={vulnLogic}
            setVulnLogic={setVulnLogic}
            onlyChanged={onlyChanged}
            setOnlyChanged={setOnlyChanged}
            hasDiff={Boolean(diff)}
          />
        </div>
      </section>

      <SummaryCards locale={locale} rows={sortedRows} diff={diff} />

      {sortedRows.length > 0 ? (
        <ResultsTable
          locale={locale}
          rows={sortedRows}
          totalRows={rows.length}
          diff={diff}
          sortKey={sortKey}
          sortDir={sortDir}
          onSort={handleSort}
          onInspect={setActive}
        />
      ) : (
        <div className="max-w-7xl mx-auto rounded-2xl border border-dashed border-slate-300 dark:border-slate-800 p-10 text-center text-sm text-slate-500 dark:text-slate-400">
          {t.noResultsYet}
        </div>
      )}

      {active && (
        <DetailModal
          locale={locale}
          result={active}
          diff={diff?.domains[active.domain]}
          onClose={() => setActive(null)}
        />
      )}
    </div>
  );
}
