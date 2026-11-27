import { CheckStatus, CheckSummary, DomainDiff, Grade } from "../types/scan";

export function StatusBadge({
  status,
  title,
}: {
  status: CheckStatus;
  title?: string;
}) {
  const styles: Record<CheckStatus, string> = {
    pass: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800",
    warn: "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800",
    fail: "bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800",
    info: "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
  };

  return (
    <span
      title={title}
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold border tracking-wide uppercase ${styles[status]}`}
    >
      {status}
    </span>
  );
}

export function GradeBadge({ grade }: { grade?: Grade }) {
  if (!grade) {
    return (
      <span className="inline-flex items-center justify-center w-9 h-7 rounded-lg text-xs font-bold bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400">
        —
      </span>
    );
  }

  const map: Record<Grade, string> = {
    "A+": "bg-emerald-600 text-white shadow-sm shadow-emerald-600/30",
    A: "bg-emerald-500 text-white",
    B: "bg-sky-500 text-white",
    C: "bg-amber-500 text-white",
    D: "bg-orange-500 text-white",
    F: "bg-rose-600 text-white",
  };

  return (
    <span
      className={`inline-flex items-center justify-center w-9 h-7 rounded-lg text-xs font-extrabold ${map[grade]}`}
    >
      {grade}
    </span>
  );
}

export function DiffBadge({ diff }: { diff?: DomainDiff }) {
  if (!diff) return <span className="text-xs text-slate-400">—</span>;

  const delta =
    diff.scoreDelta !== undefined && diff.scoreDelta !== 0
      ? ` ${diff.scoreDelta > 0 ? `+${diff.scoreDelta}` : diff.scoreDelta}`
      : "";

  switch (diff.trend) {
    case "improved":
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300">
          ▲{delta}
        </span>
      );
    case "regressed":
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-300">
          ▼{delta}
        </span>
      );
    case "new":
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-300">
          NEW
        </span>
      );
    case "removed":
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
          DEL
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium text-slate-500 dark:text-slate-400">
          =
        </span>
      );
  }
}

export function MiniBar({ counts }: { counts: CheckSummary }) {
  const total = counts.pass + counts.warn + counts.fail + counts.info;
  if (!total) {
    return <div className="w-28 h-2.5 rounded-full bg-slate-200 dark:bg-slate-800" />;
  }

  const pct = (n: number) => `${(n / total) * 100}%`;

  return (
    <div
      className="flex w-28 h-2.5 rounded-full overflow-hidden bg-slate-200 dark:bg-slate-800"
      title={`P:${counts.pass} W:${counts.warn} F:${counts.fail} I:${counts.info}`}
    >
      {counts.pass > 0 && (
        <div className="bg-emerald-500 h-full" style={{ width: pct(counts.pass) }} />
      )}
      {counts.warn > 0 && (
        <div className="bg-amber-500 h-full" style={{ width: pct(counts.warn) }} />
      )}
      {counts.fail > 0 && (
        <div className="bg-rose-500 h-full" style={{ width: pct(counts.fail) }} />
      )}
      {counts.info > 0 && (
        <div className="bg-slate-400 h-full" style={{ width: pct(counts.info) }} />
      )}
    </div>
  );
}
