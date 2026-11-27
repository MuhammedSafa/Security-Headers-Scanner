import { Download, Globe, Moon, ShieldCheck, Sun } from "lucide-react";
import { Locale, TRANSLATIONS } from "../i18n/translations";
import { Theme } from "../hooks/useTheme";

interface HeaderBarProps {
  locale: Locale;
  setLocale: (l: Locale) => void;
  theme: Theme;
  toggleTheme: () => void;
  hasResults: boolean;
  onExportCsvSummary: () => void;
  onExportCsvDetailed: () => void;
  onExportJson: () => void;
  onExportYaml: () => void;
  onExportPdf: () => void;
}

export function HeaderBar({
  locale,
  setLocale,
  theme,
  toggleTheme,
  hasResults,
  onExportCsvSummary,
  onExportCsvDetailed,
  onExportJson,
  onExportYaml,
  onExportPdf,
}: HeaderBarProps) {
  const t = TRANSLATIONS[locale];

  const btnClass =
    "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors";

  return (
    <header className="max-w-7xl mx-auto mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-emerald-500 flex items-center justify-center text-white shadow-lg shadow-blue-600/25 shrink-0">
          <ShieldCheck className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-xl font-extrabold tracking-tight text-slate-900 dark:text-white">
            {t.appTitle}
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">{t.appSubtitle}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button className={btnClass} disabled={!hasResults} onClick={onExportCsvSummary}>
          <Download className="w-3.5 h-3.5" />
          {t.csvSummary}
        </button>
        <button className={btnClass} disabled={!hasResults} onClick={onExportCsvDetailed}>
          <Download className="w-3.5 h-3.5" />
          {t.csvDetailed}
        </button>
        <button className={btnClass} disabled={!hasResults} onClick={onExportJson}>
          {t.json}
        </button>
        <button className={btnClass} disabled={!hasResults} onClick={onExportYaml}>
          {t.downloadYaml}
        </button>
        <button className={btnClass} disabled={!hasResults} onClick={onExportPdf}>
          {t.pdf}
        </button>

        <div className="h-5 w-px bg-slate-200 dark:bg-slate-700 mx-1 hidden sm:block" />

        <button
          type="button"
          onClick={() => setLocale(locale === "tr" ? "en" : "tr")}
          className={btnClass}
          aria-label="Toggle language"
        >
          <Globe className="w-3.5 h-3.5" />
          {locale.toUpperCase()}
        </button>

        <button
          type="button"
          onClick={toggleTheme}
          className={btnClass}
          aria-label="Toggle color theme"
        >
          {theme === "dark" ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
        </button>
      </div>
    </header>
  );
}
