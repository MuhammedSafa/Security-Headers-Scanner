import { ScanDiff, ScanResult } from "../types/scan";

export type SortKey = "domain" | "score" | "status" | "fail";
export type SortDir = "asc" | "desc";

export interface FilterOptions {
  filterText: string;
  useRegex: boolean;
  vulnSel: Record<string, boolean>;
  sevFail: boolean;
  sevWarn: boolean;
  vulnLogic: "any" | "all";
  onlyChanged: boolean;
  diff: ScanDiff | null;
}

export function filterResults(
  rows: ScanResult[],
  opts: FilterOptions
): { rows: ScanResult[]; regexError: string | null } {
  let regexError: string | null = null;
  let list = rows;

  if (opts.filterText.trim()) {
    const terms = opts.filterText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    if (opts.useRegex) {
      const regexes: RegExp[] = [];
      for (const term of terms) {
        try {
          regexes.push(new RegExp(term, "i"));
        } catch (err) {
          regexError = err instanceof Error ? err.message : "Invalid regex";
          break;
        }
      }
      if (!regexError) {
        list = list.filter((r) => regexes.every((rx) => rx.test(r.domain)));
      }
    } else {
      list = list.filter((r) => {
        const lower = r.domain.toLowerCase();
        return terms.every((t) => lower.includes(t.toLowerCase()));
      });
    }
  }

  const selectedVulns = Object.entries(opts.vulnSel)
    .filter(([, enabled]) => enabled)
    .map(([k]) => k);

  if (selectedVulns.length > 0) {
    list = list.filter((r) => {
      if (!r.ok) return false;
      const matches = selectedVulns.map((k) => {
        const st = r.checks[k]?.status;
        return (opts.sevFail && st === "fail") || (opts.sevWarn && st === "warn");
      });
      return opts.vulnLogic === "all" ? matches.every(Boolean) : matches.some(Boolean);
    });
  }

  if (opts.onlyChanged && opts.diff) {
    list = list.filter((r) => {
      const d = opts.diff?.domains[r.domain];
      return d && d.trend !== "unchanged";
    });
  }

  return { rows: list, regexError };
}

export function sortResults(
  rows: ScanResult[],
  key: SortKey,
  dir: SortDir
): ScanResult[] {
  const mult = dir === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    switch (key) {
      case "domain":
        return a.domain.localeCompare(b.domain) * mult;
      case "score":
        return ((a.score ?? -1) - (b.score ?? -1)) * mult;
      case "status":
        return ((a.status ?? 0) - (b.status ?? 0)) * mult;
      case "fail":
        return (a.summary.fail - b.summary.fail) * mult;
    }
  });
}
