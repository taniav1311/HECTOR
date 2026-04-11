import { useEffect, useMemo, useRef, useState } from "react";
import { Clock3, Heart, ServerCrash } from "lucide-react";

const RISK_COLORS = {
  1: "#16a34a",
  2: "#eab308",
  3: "#f97316",
  4: "#dc2626",
};

function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }
  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function buildPlot(scans) {
  const xLabels = scans.map((scan) => formatTimestamp(scan.timestamp));
  const portSet = new Set();

  scans.forEach((scan, scanIndex) => {
    (scan.ports || []).forEach((entry) => {
      if (typeof entry.port === "number") {
        portSet.add(entry.port);
      }
    });
  });

  const yPorts = Array.from(portSet).sort((a, b) => a - b);
  const points = [];

  scans.forEach((scan, scanIndex) => {
    (scan.ports || []).forEach((entry) => {
      if (typeof entry.port !== "number") return;
      if (typeof entry.risk !== "number") return;
      const score = typeof entry.score === "number" ? Math.max(0, Math.min(10, entry.score)) : null;
      points.push({
        xIndex: scanIndex,
        yPort: entry.port,
        risk: Math.max(1, Math.min(4, entry.risk)),
        score,
      });
    });
  });

  return { xLabels, yPorts, points };
}

function PortRiskDotChart({ scans }) {
  const { xLabels, yPorts, points } = useMemo(() => buildPlot(scans), [scans]);

  if (xLabels.length === 0 || yPorts.length === 0) {
    return <p className="rounded-md border border-dashed border-white/10 bg-white/[0.02] px-3 py-4 text-sm text-white/55">No scans available</p>;
  }

  const width = Math.max(680, xLabels.length * 110);
  const height = Math.max(320, yPorts.length * 38 + 70);
  const leftPad = 64;
  const topPad = 20;
  const rightPad = 18;
  const bottomPad = 64;

  const innerWidth = width - leftPad - rightPad;
  const innerHeight = height - topPad - bottomPad;

  const xStep = xLabels.length > 1 ? innerWidth / (xLabels.length - 1) : innerWidth / 2;
  const yStep = yPorts.length > 1 ? innerHeight / (yPorts.length - 1) : innerHeight / 2;

  const yToPixel = (port) => {
    const index = yPorts.indexOf(port);
    if (index < 0) return topPad;
    return topPad + innerHeight - index * yStep;
  };

  const xToPixel = (index) => {
    if (xLabels.length === 1) return leftPad + innerWidth / 2;
    return leftPad + index * xStep;
  };

  return (
    <div className="overflow-x-auto">
      <svg width={width} height={height} className="rounded-md bg-[#0b1326]">
        <line x1={leftPad} y1={topPad} x2={leftPad} y2={topPad + innerHeight} stroke="rgba(255,255,255,0.22)" />
        <line x1={leftPad} y1={topPad + innerHeight} x2={leftPad + innerWidth} y2={topPad + innerHeight} stroke="rgba(255,255,255,0.22)" />

        {yPorts.map((port) => {
          const y = yToPixel(port);
          return (
            <g key={port}>
              <line
                x1={leftPad}
                y1={y}
                x2={leftPad + innerWidth}
                y2={y}
                stroke="rgba(255,255,255,0.08)"
                strokeDasharray="3 4"
              />
              <text x={leftPad - 10} y={y + 4} textAnchor="end" fill="rgba(255,255,255,0.7)" fontSize="12" fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace">
                {port}
              </text>
            </g>
          );
        })}

        {xLabels.map((label, index) => {
          const x = xToPixel(index);
          return (
            <g key={`${label}-${index}`}>
              <line
                x1={x}
                y1={topPad}
                x2={x}
                y2={topPad + innerHeight}
                stroke="rgba(255,255,255,0.05)"
              />
              <text
                x={x}
                y={topPad + innerHeight + 20}
                textAnchor="end"
                fill="rgba(255,255,255,0.68)"
                fontSize="11"
                transform={`rotate(-24 ${x} ${topPad + innerHeight + 20})`}
              >
                {label}
              </text>
            </g>
          );
        })}

        {points.map((point, index) => {
          const cx = xToPixel(point.xIndex);
          const cy = yToPixel(point.yPort);
          const visualScore = point.score ?? point.risk * 2.5;
          const radius = 4 + (visualScore / 10) * 4;
          return (
            <circle
              key={`${point.xIndex}-${point.yPort}-${index}`}
              cx={cx}
              cy={cy}
              r={radius}
              fill={RISK_COLORS[point.risk]}
              stroke="rgba(255,255,255,0.3)"
              strokeWidth="1"
            >
              <title>{`Port ${point.yPort} at ${xLabels[point.xIndex]} risk ${point.risk} score ${visualScore.toFixed(2)}/10`}</title>
            </circle>
          );
        })}

        <text x={leftPad + innerWidth / 2} y={height - 8} textAnchor="middle" fill="rgba(255,255,255,0.8)" fontSize="12">
          Scan Date and Time
        </text>
        <text
          x={16}
          y={topPad + innerHeight / 2}
          textAnchor="middle"
          fill="rgba(255,255,255,0.8)"
          fontSize="12"
          transform={`rotate(-90 16 ${topPad + innerHeight / 2})`}
        >
          Port Number
        </text>
      </svg>
    </div>
  );
}

export function FavouritesPanel({ apiBase, refreshToken = 0, preselectHost = null }) {
  const [favourites, setFavourites] = useState([]);
  const [selectedHost, setSelectedHost] = useState(preselectHost || "");
  const [history, setHistory] = useState(null);
  const [removingHost, setRemovingHost] = useState("");
  const lastAppliedPreselectRef = useRef("");

  const [loadingFavs, setLoadingFavs] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState(null);

  const loadFavourites = async () => {
    setLoadingFavs(true);
    setError(null);
    try {
      const response = await fetch(`${apiBase}/favourites`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Failed to load favourites.");
      }

      const items = Array.isArray(data.favourites) ? data.favourites : [];
      setFavourites(items);

      if (items.length === 0) {
        setSelectedHost("");
        setHistory(null);
      } else {
        const canApplyPreselect = (
          preselectHost
          && preselectHost !== lastAppliedPreselectRef.current
          && items.includes(preselectHost)
        );

        if (canApplyPreselect) {
          setSelectedHost(preselectHost);
          lastAppliedPreselectRef.current = preselectHost;
        } else if (!selectedHost || !items.includes(selectedHost)) {
          setSelectedHost(items[0]);
        }
      }
    } catch (fetchError) {
      setError(fetchError.message || "Failed to load favourites.");
    } finally {
      setLoadingFavs(false);
    }
  };

  const loadHistory = async (host) => {
    if (!host) {
      setHistory(null);
      return;
    }

    setLoadingHistory(true);
    setError(null);
    try {
      const response = await fetch(`${apiBase}/history/${encodeURIComponent(host)}`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Failed to load history.");
      }
      setHistory(data);
    } catch (fetchError) {
      setError(fetchError.message || "Failed to load history.");
      setHistory(null);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    loadFavourites();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiBase, refreshToken]);

  useEffect(() => {
    loadHistory(selectedHost);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedHost, apiBase, refreshToken]);

  const scans = history?.scans || [];

  const handleRemoveFavourite = async (host) => {
    setRemovingHost(host);
    setError(null);

    try {
      const response = await fetch(`${apiBase}/favourite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: host, favourite: false }),
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to remove favourite.");
      }

      setFavourites((current) => {
        const next = current.filter((item) => item !== host);
        if (next.length === 0) {
          setSelectedHost("");
          setHistory(null);
        } else if (selectedHost === host) {
          setSelectedHost(next[0]);
        }
        return next;
      });
    } catch (removeError) {
      setError(removeError.message || "Failed to remove favourite.");
    } finally {
      setRemovingHost("");
    }
  };

  return (
    <section className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 shadow-2xl shadow-black/20 backdrop-blur-xl">
      <div className="mb-5 flex items-center justify-between gap-4">
        <div>
          <h3 className="text-xl font-semibold text-white">Favourites</h3>
          <p className="mt-2 text-sm text-white/55">View time-based risk points across scans for every open port.</p>
        </div>
        <div className="rounded-xl border border-white/10 bg-black/20 px-4 py-2 text-right">
          <p className="text-[10px] uppercase tracking-[0.25em] text-white/45">Saved Hosts</p>
          <p className="mt-1 text-lg font-semibold text-cyan-200">{favourites.length}</p>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
        <div className="rounded-xl border border-white/10 bg-black/20 p-3">
          <p className="mb-2 text-xs uppercase tracking-[0.25em] text-white/45">Hosts</p>

          {loadingFavs ? (
            <p className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white/60">Loading favourites...</p>
          ) : favourites.length === 0 ? (
            <p className="rounded-lg border border-dashed border-white/10 bg-white/[0.03] px-3 py-4 text-sm text-white/55">No favourites yet. Use the heart in Scan Target.</p>
          ) : (
            <div className="space-y-2">
              {favourites.map((host) => {
                const active = host === selectedHost;
                return (
                  <div
                    key={host}
                    className={`flex items-center gap-2 rounded-lg border px-2 py-2 transition-colors ${active ? "border-cyan-400/50 bg-cyan-500/10" : "border-white/10 bg-white/[0.02] hover:bg-white/[0.05]"}`}
                  >
                    <button
                      type="button"
                      onClick={() => setSelectedHost(host)}
                      className={`min-w-0 flex-1 truncate text-left text-sm ${active ? "text-cyan-100" : "text-white/70"}`}
                      title={host}
                    >
                      {host}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleRemoveFavourite(host)}
                      disabled={removingHost === host}
                      title={`Remove ${host} from favourites`}
                      aria-label={`Remove ${host} from favourites`}
                      className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-red-400/35 bg-red-500/10 text-red-300 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      <Heart className="h-4 w-4 fill-red-300 text-red-300" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-white/10 bg-black/20 p-4">
          {!selectedHost ? (
            <div className="flex h-full min-h-[260px] items-center justify-center rounded-lg border border-dashed border-white/10 bg-white/[0.02] text-sm text-white/50">
              Select a favourited host to inspect scan history.
            </div>
          ) : loadingHistory ? (
            <div className="flex h-full min-h-[260px] items-center justify-center rounded-lg border border-white/10 bg-white/[0.02] text-sm text-white/60">
              Loading scan history...
            </div>
          ) : scans.length === 0 ? (
            <div className="min-h-[260px] rounded-lg border border-dashed border-white/10 bg-white/[0.02] p-4">
              <div className="flex items-center gap-2 text-white/70">
                <ServerCrash className="h-4 w-4" />
                <p className="text-sm font-semibold">No scans available</p>
              </div>
              <p className="mt-2 text-sm text-white/55">Host {selectedHost} is favourited, but no scan snapshot has been saved yet.</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid gap-2 sm:grid-cols-3">
                <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
                  <p className="text-[10px] uppercase tracking-[0.22em] text-white/45">Selected Host</p>
                  <p className="mt-1 font-mono text-sm text-white">{selectedHost}</p>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
                  <p className="text-[10px] uppercase tracking-[0.22em] text-white/45">Total Scans</p>
                  <p className="mt-1 text-sm font-semibold text-cyan-200">{scans.length}</p>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
                  <p className="text-[10px] uppercase tracking-[0.22em] text-white/45">Latest Scan</p>
                  <p className="mt-1 flex items-center gap-1 text-sm text-white/80">
                    <Clock3 className="h-3.5 w-3.5" />
                    {formatTimestamp(scans[scans.length - 1].timestamp)}
                  </p>
                </div>
              </div>

              <div className="rounded-lg border border-white/10 bg-[#0a1223] p-3">
                <div className="mb-3 flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">Port Risk Dot Plot</p>
                    <p className="text-[11px] text-white/45">Historical scans captured from localhost while the backend simulator changes open ports.</p>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-white/70">
                    <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-green-600" />Low</span>
                    <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-yellow-500" />Medium</span>
                    <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-orange-500" />High</span>
                    <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-red-600" />Critical</span>
                  </div>
                </div>

                <PortRiskDotChart scans={scans} />
                <p className="mt-2 text-xs text-white/50">Dot color = risk level, dot size = risk score (larger means higher score).</p>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2 text-xs text-white/55">
        <Heart className="h-3.5 w-3.5 text-red-300" />
        Last 5 scan snapshots are retained per favourited host.
      </div>
    </section>
  );
}
