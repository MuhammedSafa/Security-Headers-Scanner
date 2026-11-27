import { describe, expect, it } from "vitest";
import { csvEscape, escapeHtml, isSafeHttpUrl } from "./export";

describe("export security utilities", () => {
  it("neutralizes CSV formula injection payloads", () => {
    expect(csvEscape("=CMD|' /C calc'!A0")).toBe("'=CMD|' /C calc'!A0");
    expect(csvEscape("+2+3")).toBe("'+2+3");
    expect(csvEscape("-1+1")).toBe("'-1+1");
    expect(csvEscape("@SUM(1,2)")).toBe('"\'@SUM(1,2)"');
    expect(csvEscape("normal,value")).toBe('"normal,value"');
    expect(csvEscape('=1,"quoted"')).toBe('"\'=1,""quoted"""');
  });

  it("escapes all critical HTML characters", () => {
    expect(escapeHtml(`<script>"alert('x')&"</script>`)).toBe(
      "&lt;script&gt;&quot;alert(&#39;x&#39;)&amp;&quot;&lt;/script&gt;"
    );
  });

  it("validates http and https URLs only", () => {
    expect(isSafeHttpUrl("https://example.com/app")).toBe(true);
    expect(isSafeHttpUrl("http://example.com")).toBe(true);
    expect(isSafeHttpUrl("javascript:alert(1)")).toBe(false);
    expect(isSafeHttpUrl("data:text/html,<h1>x</h1>")).toBe(false);
    expect(isSafeHttpUrl("")).toBe(false);
  });
});
