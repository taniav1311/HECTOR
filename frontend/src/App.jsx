import { useState } from "react";
import { ChevronRight, Heart, Radar, Shield, Terminal } from "lucide-react";
import { HeroGeometric } from "@/components/ui/shape-landing-hero";
import { DetailedAnalysisPanel } from "@/components/DetailedAnalysisPanel";
import { FavouritesPanel } from "@/components/FavouritesPanel";

const API_BASE = "http://localhost:5000";
const API_URL = `${API_BASE}/scan`;

const SEVERITY_STYLES = {
  CRITICAL: {
    badge: "bg-red-600 text-white",
    row: "border-l-4 border-red-600",
  },
  HIGH: {
    badge: "bg-orange-500 text-white",
    row: "border-l-4 border-orange-500",
  },
  MEDIUM: {
    badge: "bg-yellow-400 text-gray-900",
    row: "border-l-4 border-yellow-400",
  },
  LOW: {
    badge: "bg-green-500 text-white",
    row: "border-l-4 border-green-500",
  },
};

function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] ?? "bg-gray-500 text-white";
  return (
    <span className={`rounded px-2 py-1 text-xs font-bold uppercase ${typeof style === "string" ? style : style.badge}`}>
      {severity ?? "UNKNOWN"}
    </span>
  );
}

function FindingsTable({ findings, onRowClick }) {
  if (findings.length === 0) {
    return <p className="py-8 text-center text-gray-400">No open ports or findings detected.</p>;
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-700">
      <table className="w-full text-left text-sm">
        <thead className="bg-gray-800 text-xs uppercase tracking-wider text-gray-300">
          <tr>
            <th className="px-4 py-3">Port</th>
            <th className="px-4 py-3">Service</th>
            <th className="px-4 py-3">Risk Score</th>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">CVE</th>
            <th className="px-4 py-3">Attack Type</th>
            <th className="px-4 py-3">Threat</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-700">
          {findings.map((finding, index) => {
            const rowStyle = SEVERITY_STYLES[finding.severity]?.row ?? "";
            return (
              <tr
                key={index}
                onClick={() => onRowClick(finding)}
                className={`bg-gray-900 transition-colors hover:bg-gray-800 cursor-pointer ${rowStyle}`}
              >
                <td className="px-4 py-3 font-mono font-semibold text-gray-100">{finding.port}</td>
                <td className="px-4 py-3 uppercase tracking-wide text-gray-300">{finding.service}</td>
                <td className="px-4 py-3">
                  <span className="font-bold text-gray-100">{finding.risk_score.toFixed(1)}</span>
                  <span className="text-gray-500"> / 10</span>
                </td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={finding.severity} />
                </td>
                <td className="px-4 py-3">
                  {finding.cve ? (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                      target="_blank"
                      rel="noreferrer"
                      className="font-mono text-xs text-blue-400 underline hover:text-blue-300"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {finding.cve}
                    </a>
                  ) : (
                    <span className="text-xs text-gray-500">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center rounded-full border border-blue-400/30 bg-blue-500/10 px-2.5 py-1 text-xs font-semibold uppercase tracking-wider text-blue-200">
                    {finding.attack_type ?? "Unknown"}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs font-semibold leading-relaxed text-red-300">
                  {finding.structured_explanation?.threat ?? "Service Exposure Risk"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SummaryBar({ target, findings, ipSummary, model, performance }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach((finding) => {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  });

  const aggregateScore = ipSummary?.aggregate_risk_score ?? 0;
  const weightedScore = ipSummary?.weighted_risk_score ?? 0;
  const systemStatus = ipSummary?.system_status ?? "LOW RISK";
  const mostDangerousPort = findings.length > 0 ? findings[0].port : "-";
  const scanTimeSeconds = performance?.scan_time_seconds ?? 0;

  return (
    <div className="mb-6 rounded-lg border border-gray-700 bg-gray-800 p-4">
      <div className="mb-4 rounded-xl border border-slate-600 bg-slate-950/60 p-4 shadow-inner">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <div>
            <p className="text-xs uppercase tracking-wider text-gray-400">Target</p>
            <p className="mt-1 font-mono text-lg font-semibold text-white">{target}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wider text-gray-400">Final Risk</p>
            <p className="mt-1 text-lg font-semibold text-red-300">{systemStatus}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wider text-gray-400">Most Dangerous Port</p>
            <p className="mt-1 text-lg font-semibold text-white">{mostDangerousPort}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 items-stretch gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-gray-700 bg-gray-900 p-3">
          <p className="text-xs uppercase text-gray-400">Vulnerability Severity Index</p>
          <p className="text-2xl font-bold text-white">{aggregateScore.toFixed(2)} / 10</p>
          <p className="mt-1 text-xs font-semibold text-red-300">System Status: {systemStatus}</p>
          <p className="mt-2 text-xs text-gray-500">Weighted Baseline: {weightedScore.toFixed(2)} / 10</p>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-4">
        <div className="flex gap-4">
          {Object.entries(counts).map(([level, count]) => (
            <div key={level} className="text-center">
              <p className="text-xs uppercase text-gray-400">{level}</p>
              <p
                className={`text-xl font-bold ${level === "CRITICAL" ? "text-red-500" : level === "HIGH" ? "text-orange-400" : level === "MEDIUM" ? "text-yellow-400" : "text-green-400"}`}
              >
                {count}
              </p>
            </div>
          ))}
        </div>
        <div className="text-center">
          <p className="text-xs uppercase text-gray-400">Total Findings</p>
          <p className="text-xl font-bold text-gray-100">{findings.length}</p>
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-gray-700 bg-gray-900 p-3">
        <p className="mb-1 text-xs uppercase text-gray-400">Scoring Model</p>
        <p className="text-xs text-gray-300">{model?.description ?? "Risk Score computed using weighted hybrid model combining heuristic severity and CVSS."}</p>
        <p className="mt-1 font-mono text-xs text-blue-300">{model?.formula ?? "port_score = 0.4 * heuristic_score + 0.6 * cvss_score"}</p>
        <p className="mt-2 text-xs text-gray-400">Scan Time: {scanTimeSeconds.toFixed(2)} seconds</p>
      </div>
    </div>
  );
}

function SectionButton({ active, icon: Icon, label, description, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex w-full items-start gap-3 rounded-2xl border px-4 py-4 text-left transition-all duration-200 ${active ? "border-cyan-400/50 bg-cyan-500/10 shadow-lg shadow-cyan-500/10" : "border-white/10 bg-white/[0.03] hover:bg-white/[0.06]"}`}
    >
      <span className={`mt-0.5 inline-flex h-10 w-10 items-center justify-center rounded-xl ${active ? "bg-cyan-500 text-white" : "bg-white/10 text-cyan-200"}`}>
        <Icon className="h-5 w-5" />
      </span>
      <span className="min-w-0">
        <span className="block text-sm font-semibold tracking-wide text-white">{label}</span>
        <span className="mt-1 block text-xs leading-relaxed text-white/50">{description}</span>
      </span>
    </button>
  );
}

function MainWorkspace() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [favouriteBusy, setFavouriteBusy] = useState(false);
  const [isFavourite, setIsFavourite] = useState(false);
  const [favouritesRefreshToken, setFavouritesRefreshToken] = useState(0);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [section, setSection] = useState("scan");
  const [selectedFinding, setSelectedFinding] = useState(null);

  const handleScan = async () => {
    const trimmed = target.trim();
    if (!trimmed) {
      setError("Please enter an IP address, domain, or URL.");
      return;
    }

    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: trimmed }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error ?? `Server error: ${response.status}`);
        return;
      }

      setReport(data);
      setIsFavourite(Boolean(data.favourite));
      setSection("report");
    } catch (scanError) {
      setError("Could not reach the API. Make sure the Flask server is running on port 5000.");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter") handleScan();
  };

  const handleReset = () => {
    setTarget("");
    setIsFavourite(false);
    setError(null);
    setReport(null);
    setSection("scan");
  };

  const handleToggleFavourite = async () => {
    const activeTarget = (target || report?.scan_host || "").trim();
    if (!activeTarget || favouriteBusy) {
      setError("Enter a target or run a scan before toggling favourite.");
      return;
    }

    setFavouriteBusy(true);
    setError(null);
    const nextFavourite = !isFavourite;

    try {
      const response = await fetch(`${API_BASE}/favourite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: activeTarget, favourite: nextFavourite }),
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.error ?? "Failed to update favourite status.");
        return;
      }

      const updatedFavourite = Boolean(data.favourite);
      setIsFavourite(updatedFavourite);

      // If user favourites after a scan is already on screen, save that exact scan snapshot.
      if (
        updatedFavourite
        && report?.results?.length
        && (report?.scan_host === activeTarget || report?.target === activeTarget)
      ) {
        await fetch(`${API_BASE}/history/save`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: report.scan_host || activeTarget,
            findings: report.results,
          }),
        });
      }

      setFavouritesRefreshToken((value) => value + 1);
    } catch (favouriteError) {
      setError("Could not update favourite status. Please try again.");
    } finally {
      setFavouriteBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#030712] px-4 py-10 text-white sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-8">
        <header className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.32em] text-cyan-200/70">HECTOR Workspace</p>
              <h2 className="mt-3 text-3xl font-black tracking-tight sm:text-4xl">Security assessment dashboard</h2>
              <p className="mt-3 max-w-2xl text-sm leading-7 text-white/55">
                Monitor attack surface, identify critical exposures, and understand risks through intelligent vulnerability mapping.
              </p>
            </div>
            <div className="grid grid-cols-3 gap-3 text-center text-xs text-white/60 sm:min-w-[360px]">
              <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
                <p className="text-[10px] uppercase tracking-[0.3em] text-white/35">Target</p>
                <p className="mt-1 font-mono text-sm text-white">{report?.target ?? (target || "-")}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
                <p className="text-[10px] uppercase tracking-[0.3em] text-white/35">Findings</p>
                <p className="mt-1 text-sm text-white">{report?.results?.length ?? 0}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
                <p className="text-[10px] uppercase tracking-[0.3em] text-white/35">Status</p>
                <p className="mt-1 text-sm text-cyan-200">{loading ? "Scanning" : report ? "Ready" : "Idle"}</p>
              </div>
            </div>
          </div>
        </header>

        <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
          <aside className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-4 shadow-2xl shadow-black/20 backdrop-blur-xl">
            <div className="mb-4 flex items-center gap-2 px-2 text-xs uppercase tracking-[0.3em] text-white/45">
              <Terminal className="h-4 w-4" />
              Navigation
            </div>
            <div className="space-y-3">
              <SectionButton active={section === "scan"} icon={Radar} label="Scan Target" description="Enter an IP, domain, or URL and start a new assessment run." onClick={() => setSection("scan")} />
              <SectionButton active={section === "report"} icon={ChevronRight} label="Findings Report" description="Detailed port-by-port results and attack context." onClick={() => setSection("report")} />
              <SectionButton active={section === "overview"} icon={Shield} label="Risk Overview" description="Summary metrics, exposure counts, and system status." onClick={() => setSection("overview")} />
              <SectionButton active={section === "favourites"} icon={Heart} label="Favourites" description="Track scan history and temporal risk heatmaps." onClick={() => setSection("favourites")} />
            </div>
          </aside>

          <main className="space-y-6">
            {section === "overview" && (
              <section className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 shadow-2xl shadow-black/20 backdrop-blur-xl">
                {report ? (
                  <SummaryBar target={report.target} findings={report.results} ipSummary={report.ip_summary} model={report.model} performance={report.performance} />
                ) : (
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="rounded-2xl border border-white/10 bg-black/20 p-5">
                      <p className="text-xs uppercase tracking-[0.3em] text-white/40">Overview</p>
                      <p className="mt-2 text-lg font-semibold text-white">No scan data yet</p>
                      <p className="mt-2 text-sm leading-6 text-white/50">Run a target scan to populate the risk index, exposure count, and severity breakdown.</p>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-black/20 p-5">
                      <p className="text-xs uppercase tracking-[0.3em] text-white/40">Exposure</p>
                      <p className="mt-2 text-lg font-semibold text-white">Ready for assessment</p>
                      <p className="mt-2 text-sm leading-6 text-white/50">The workspace is structured so the high-level view stays readable before any report is opened.</p>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-black/20 p-5">
                      <p className="text-xs uppercase tracking-[0.3em] text-white/40">Status</p>
                      <p className="mt-2 text-lg font-semibold text-white">Idle</p>
                      <p className="mt-2 text-sm leading-6 text-white/50">Use the Scan Target section to begin the first assessment.</p>
                    </div>
                  </div>
                )}
              </section>
            )}

            {section === "scan" && (
              <section className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 shadow-2xl shadow-black/20 backdrop-blur-xl">
                <div className="mb-5">
                  <h3 className="text-xl font-semibold text-white">Target Scan</h3>
                  <p className="mt-2 text-sm text-white/50">Enter one IP, domain, or URL and run the scanner from here.</p>
                </div>

                <label className="mb-2 block text-xs uppercase tracking-[0.3em] text-white/40">Target (IP / Domain / URL)</label>
                <div className="flex flex-col gap-3 sm:flex-row">
                  <input
                    type="text"
                    value={target}
                    onChange={(event) => {
                      setTarget(event.target.value);
                      if (!report || (report.scan_host && event.target.value.trim() !== report.scan_host)) {
                        setIsFavourite(false);
                      }
                    }}
                    onKeyDown={handleKeyDown}
                    placeholder="e.g. 127.0.0.1, example.com, https://example.com"
                    disabled={loading}
                    className="flex-1 rounded-2xl border border-white/10 bg-black/30 px-4 py-3 font-mono text-sm text-white placeholder:text-white/25 focus:outline-none focus:ring-2 focus:ring-cyan-400/50 disabled:opacity-50"
                  />
                  <button
                    type="button"
                    onClick={handleToggleFavourite}
                    disabled={loading || favouriteBusy}
                    title={isFavourite ? "Remove from favourites" : "Add to favourites"}
                    aria-label={isFavourite ? "Remove from favourites" : "Add to favourites"}
                    className={`inline-flex h-12 w-12 items-center justify-center rounded-2xl border transition-colors ${isFavourite ? "border-red-400/50 bg-red-500/10 text-red-200" : "border-white/20 bg-white/5 text-white/80 hover:bg-white/10"} disabled:cursor-not-allowed disabled:opacity-60`}
                  >
                    <Heart className={`h-5 w-5 ${isFavourite ? "fill-red-300 text-red-300" : "text-white/70"}`} />
                  </button>
                  <button
                    type="button"
                    onClick={handleScan}
                    disabled={loading}
                    className="rounded-2xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition-transform hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {loading ? "Scanning..." : "Scan Target"}
                  </button>
                  <button
                    type="button"
                    onClick={handleReset}
                    disabled={loading}
                    className="rounded-2xl border border-white/20 bg-white/5 px-6 py-3 text-sm font-semibold text-white/90 transition-colors hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Reset
                  </button>
                </div>

                {loading && <div className="mt-6 rounded-2xl border border-white/10 bg-black/20 px-5 py-4 text-sm text-white/60">Running scan. This can take a few seconds.</div>}

                {error && !loading && <div className="mt-6 rounded-2xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-200">{error}</div>}
              </section>
            )}

            {section === "report" && (
              <section className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 shadow-2xl shadow-black/20 backdrop-blur-xl">
                <div className="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <h3 className="text-xl font-semibold text-white">Findings Report</h3>
                    <p className="mt-2 text-sm text-white/50">Port-level results, exposure context, and CVE references. Click any row for detailed analysis.</p>
                  </div>
                  {report ? (
                    <div className="flex items-center gap-3">
                      <span className="text-sm text-cyan-200">{report.results.length} findings loaded</span>
                      <button
                        type="button"
                        onClick={handleToggleFavourite}
                        disabled={favouriteBusy}
                        title={isFavourite ? "Remove from favourites" : "Add to favourites"}
                        aria-label={isFavourite ? "Remove from favourites" : "Add to favourites"}
                        className={`inline-flex h-9 w-9 items-center justify-center rounded-xl border transition-colors ${isFavourite ? "border-red-400/50 bg-red-500/10 text-red-200" : "border-white/20 bg-white/5 text-white/80 hover:bg-white/10"} disabled:cursor-not-allowed disabled:opacity-60`}
                      >
                        <Heart className={`h-4 w-4 ${isFavourite ? "fill-red-300 text-red-300" : "text-white/70"}`} />
                      </button>
                    </div>
                  ) : (
                    <span className="text-sm text-white/35">No report loaded yet</span>
                  )}
                </div>

                {report ? (
                  <FindingsTable findings={report.results} onRowClick={setSelectedFinding} />
                ) : (
                  <div className="rounded-2xl border border-dashed border-white/10 bg-black/20 px-5 py-10 text-center text-sm text-white/45">
                    Run a scan first to view the report table.
                  </div>
                )}
              </section>
            )}

            {section === "favourites" && (
              <FavouritesPanel
                apiBase={API_BASE}
                refreshToken={favouritesRefreshToken}
                preselectHost={report?.scan_host ?? null}
              />
            )}
          </main>
        </div>
      </div>

      {/* Detailed Analysis Panel */}
      {selectedFinding && (
        <DetailedAnalysisPanel
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}

export default function App() {
  const [screen, setScreen] = useState("home");

  return screen === "home" ? (
    <HeroGeometric
      title="HECTOR"
      subtitle="Hybrid Explainable CVE-based Threat Observation and Risk-analysis"
      actionLabel="Open Research Console"
      onAction={() => setScreen("main")}
    />
  ) : (
    <MainWorkspace />
  );
}