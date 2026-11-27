import { describe, expect, it } from "vitest";
import { ScanResult } from "../types/scan";
import { filterResults, sortResults } from "./filters";

function makeRow(domain: string, score: number, hstsFail: boolean, cspWarn: boolean): ScanResult {
  return {
    domain,
    ok: true,
    status: 200,
    finalUrl: `https://${domain}/`,
    httpsEnforced: true,
    httpRedirectedToHttps: true,
    redirectChain: [],
    durationMs: 100,
    score,
    grade: score >= 85 ? "A" : "C",
    summary: { pass: 10, warn: cspWarn ? 1 : 0, fail: hstsFail ? 1 : 0, info: 1 },
    checks: {
      hsts: {
        key: "hsts",
        header: "Strict-Transport-Security",
        status: hstsFail ? "fail" : "pass",
        code: hstsFail ? "hsts.missing" : "hsts.strong",
        value: "",
        reason: "",
      },
      csp: {
        key: "csp",
        header: "Content-Security-Policy",
        status: cspWarn ? "warn" : "pass",
        code: cspWarn ? "csp.weak_directives" : "csp.strong",
        value: "",
        reason: "",
      },
    },
    rawHeaders: {},
  };
}

describe("filterResults & sortResults", () => {
  const sample = [
    makeRow("alpha.example.com", 95, false, false),
    makeRow("beta.gov.tr", 60, true, false),
    makeRow("gamma.gov.tr", 50, true, true),
  ];

  it("filters by domain text and reports invalid regex", () => {
    const ok = filterResults(sample, {
      filterText: "gov.tr",
      useRegex: false,
      vulnSel: {},
      sevFail: true,
      sevWarn: true,
      vulnLogic: "any",
      onlyChanged: false,
      diff: null,
    });
    expect(ok.regexError).toBeNull();
    expect(ok.rows.map((r) => r.domain)).toEqual(["beta.gov.tr", "gamma.gov.tr"]);

    const bad = filterResults(sample, {
      filterText: "[unclosed",
      useRegex: true,
      vulnSel: {},
      sevFail: true,
      sevWarn: true,
      vulnLogic: "any",
      onlyChanged: false,
      diff: null,
    });
    expect(bad.regexError).not.toBeNull();
  });

  it("filters by vulnerability with AND/OR logic", () => {
    const orRes = filterResults(sample, {
      filterText: "",
      useRegex: false,
      vulnSel: { hsts: true, csp: true },
      sevFail: true,
      sevWarn: true,
      vulnLogic: "any",
      onlyChanged: false,
      diff: null,
    });
    expect(orRes.rows.map((r) => r.domain)).toEqual(["beta.gov.tr", "gamma.gov.tr"]);

    const andRes = filterResults(sample, {
      filterText: "",
      useRegex: false,
      vulnSel: { hsts: true, csp: true },
      sevFail: true,
      sevWarn: true,
      vulnLogic: "all",
      onlyChanged: false,
      diff: null,
    });
    expect(andRes.rows.map((r) => r.domain)).toEqual(["gamma.gov.tr"]);
  });

  it("sorts by score descending", () => {
    const sorted = sortResults(sample, "score", "desc");
    expect(sorted.map((r) => r.domain)).toEqual([
      "alpha.example.com",
      "beta.gov.tr",
      "gamma.gov.tr",
    ]);
  });
});
