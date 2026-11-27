import { useCallback, useRef, useState } from "react";
import { ScanDiff, ScanResult, ScanSnapshot } from "../types/scan";

export interface ScannerState {
  loading: boolean;
  done: number;
  total: number;
  statusMessage: string;
  error: string | null;
  rows: ScanResult[];
  snapshot: ScanSnapshot | null;
  diff: ScanDiff | null;
}

export function useScanner() {
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(0);
  const [total, setTotal] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<ScanResult[]>([]);
  const [snapshot, setSnapshot] = useState<ScanSnapshot | null>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  const cancelScan = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
    setStatusMessage("cancelled");
  }, []);

  const loadPreviousScan = useCallback(async (): Promise<boolean> => {
    setError(null);
    try {
      const res = await fetch("/api/last-scan");
      if (!res.ok) throw new Error(`API ${res.status}`);
      const data: { snapshot: ScanSnapshot | null } = await res.json();
      if (!data.snapshot) {
        return false;
      }
      setSnapshot(data.snapshot);
      setRows(data.snapshot.results);
      setDiff(null);
      setDone(data.snapshot.total);
      setTotal(data.snapshot.total);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return false;
    }
  }, []);

  const compareWithYaml = useCallback(
    async (baselineYaml: string): Promise<boolean> => {
      if (!rows.length) return false;
      setError(null);
      const currentSnapshot: ScanSnapshot = snapshot ?? {
        version: 1,
        timestamp: new Date().toISOString(),
        total: rows.length,
        succeeded: rows.filter((r) => r.ok).length,
        failed: rows.filter((r) => !r.ok).length,
        results: rows,
      };
      try {
        const res = await fetch("/api/diff", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            baselineYaml,
            current: currentSnapshot,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || `API ${res.status}`);
        }
        setDiff(data.diff);
        return true;
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        return false;
      }
    },
    [rows, snapshot]
  );

  const runScan = useCallback(async (domains: string[]) => {
    if (!domains.length) return;

    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    setLoading(true);
    setError(null);
    setRows([]);
    setSnapshot(null);
    setDiff(null);
    setDone(0);
    setTotal(domains.length);
    setStatusMessage("scanning");

    try {
      const response = await fetch("/api/scan/stream", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        body: JSON.stringify({ domains, saveSnapshot: true }),
        signal: ctrl.signal,
      });

      if (!response.ok) {
        let msg = `API ${response.status}`;
        try {
          const j = await response.json();
          if (j?.error) msg = j.error;
        } catch {
          // ignore
        }
        throw new Error(msg);
      }

      if (!response.body) {
        throw new Error("Streaming response body is unavailable");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      const processBlock = (block: string) => {
        const lines = block.split(/\r?\n/);
        let eventName = "message";
        const dataLines: string[] = [];

        for (const line of lines) {
          if (line.startsWith("event:")) {
            eventName = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            dataLines.push(line.slice(5).trim());
          }
        }

        if (!dataLines.length) return;
        const payload = JSON.parse(dataLines.join("\n"));

        if (eventName === "start") {
          setTotal(payload.total ?? domains.length);
        } else if (eventName === "result") {
          setDone(payload.done ?? 0);
          if (payload.result) {
            setRows((prev) => [...prev, payload.result as ScanResult]);
          }
        } else if (eventName === "done") {
          if (payload.snapshot) {
            setSnapshot(payload.snapshot as ScanSnapshot);
            setRows((payload.snapshot as ScanSnapshot).results);
          }
          if (payload.diff) {
            setDiff(payload.diff as ScanDiff);
          }
          setStatusMessage("completed");
        }
      };

      while (true) {
        const { value, done: streamDone } = await reader.read();
        if (value) {
          buffer += decoder.decode(value, { stream: true });
          const blocks = buffer.split(/\r?\n\r?\n/);
          buffer = blocks.pop() ?? "";
          for (const block of blocks) {
            if (block.trim()) processBlock(block);
          }
        }
        if (streamDone) {
          if (buffer.trim()) processBlock(buffer);
          break;
        }
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatusMessage("cancelled");
      } else {
        setError(err instanceof Error ? err.message : String(err));
        setStatusMessage("");
      }
    } finally {
      if (abortRef.current === ctrl) {
        abortRef.current = null;
      }
      setLoading(false);
    }
  }, []);

  return {
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
  };
}
