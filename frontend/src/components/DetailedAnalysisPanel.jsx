import { AlertOctagon, Binary, Calculator, Shield, Swords, Wrench, X } from "lucide-react";

const RISK_STYLES = {
  CRITICAL: { label: "Critical", text: "text-red-300", bg: "bg-red-500/10", border: "border-red-500/30" },
  HIGH: { label: "High", text: "text-orange-300", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  MEDIUM: { label: "Medium", text: "text-yellow-300", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  LOW: { label: "Low", text: "text-green-300", bg: "bg-green-500/10", border: "border-green-500/30" },
};

const PORT_INTEL = {
  21: {
    protocol: "FTP",
    commonAbuse: "Anonymous access, credential brute force, malicious file upload.",
    checks: ["Disable anonymous FTP", "Enforce FTPS/SFTP", "Restrict upload directories"],
  },
  22: {
    protocol: "SSH",
    commonAbuse: "Credential brute force, weak key/cipher policy, root login abuse.",
    checks: ["Disable root login", "Key-based auth only", "Rate-limit failed logins"],
  },
  23: {
    protocol: "Telnet",
    commonAbuse: "Plaintext credential capture and remote shell takeover.",
    checks: ["Disable Telnet", "Migrate to SSH", "Block internet exposure"],
  },
  25: {
    protocol: "SMTP",
    commonAbuse: "Open relay abuse, spoofing, mail service reconnaissance.",
    checks: ["Disable open relay", "Enforce SMTP auth", "Enable SPF/DKIM/DMARC"],
  },
  53: {
    protocol: "DNS",
    commonAbuse: "Zone transfer leakage, amplification abuse, poisoning attempts.",
    checks: ["Restrict AXFR", "Disable open recursion", "Enable DNSSEC where possible"],
  },
  80: {
    protocol: "HTTP",
    commonAbuse: "Web app enumeration and exploit chaining through exposed routes.",
    checks: ["Patch web stack", "Disable debug endpoints", "Add WAF and security headers"],
  },
  443: {
    protocol: "HTTPS",
    commonAbuse: "Application exploit over TLS, weak cipher/protocol configuration.",
    checks: ["Patch framework/deps", "Disable weak TLS versions", "Review auth/session controls"],
  },
  445: {
    protocol: "SMB",
    commonAbuse: "Lateral movement, remote code execution, share abuse.",
    checks: ["Disable SMBv1", "Limit SMB to internal network", "Audit share ACLs"],
  },
  3306: {
    protocol: "MySQL",
    commonAbuse: "Credential stuffing and direct database access abuse.",
    checks: ["Restrict DB source IPs", "Rotate credentials", "Require TLS to DB"],
  },
  3389: {
    protocol: "RDP",
    commonAbuse: "Brute force and remote desktop session hijacking.",
    checks: ["Require VPN/bastion", "Enable MFA", "Enable NLA and patch host"],
  },
  5432: {
    protocol: "PostgreSQL",
    commonAbuse: "Unauthorized DB access and privilege escalation through weak role model.",
    checks: ["Harden pg_hba.conf", "Remove unnecessary superusers", "Enable audit logging"],
  },
};

function exploitability(score) {
  if (score >= 8.5) return "Easy";
  if (score >= 7) return "Moderate";
  if (score >= 5) return "Requires Skill";
  return "Difficult";
}

function metricClass(risk) {
  return RISK_STYLES[risk] || RISK_STYLES.LOW;
}

function getPortIntel(finding) {
  return (
    PORT_INTEL[finding.port] || {
      protocol: (finding.service || "tcp").toUpperCase(),
      commonAbuse: "Service fingerprinting followed by targeted exploit attempts against discovered version/configuration.",
      checks: [
        "Restrict source IP access to this port",
        "Patch service and remove default credentials",
        "Add monitoring and alerting for this port",
      ],
    }
  );
}

function SmallMetric({ label, value, className = "text-white" }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
      <p className="text-[10px] uppercase tracking-[0.22em] text-white/45">{label}</p>
      <p className={`mt-1 text-sm font-semibold ${className}`}>{value}</p>
    </div>
  );
}

export function DetailedAnalysisPanel({ finding, onClose }) {
  if (!finding) return null;

  const style = metricClass(finding.severity);
  const intel = getPortIntel(finding);
  const details = finding.structured_explanation || {};
  const calculation = finding.risk_calculation || {};

  const cause = details.cause || finding.explanation || "No explicit cause available.";
  const impact = details.impact || "Potential compromise impact is present but not fully described.";
  const threat = details.threat || "Service Exposure Risk";

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      <aside
        className="absolute right-0 top-0 h-full w-full max-w-[820px] border-l border-white/10 bg-gradient-to-br from-gray-900 via-gray-900 to-black"
        style={{ animation: "slideInFromRight 0.26s ease-out" }}
      >
        <style>{`
          @keyframes slideInFromRight {
            from { transform: translateX(100%); }
            to { transform: translateX(0); }
          }
        `}</style>

        <div className="flex h-full flex-col">
          <header className="border-b border-white/10 bg-black/35 px-5 py-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.3em] text-white/45">Detailed Analysis</p>
                <h2 className="mt-1 text-xl font-bold text-white">Port {finding.port} - {String(finding.service || "unknown").toUpperCase()}</h2>
                <p className="mt-1 text-sm text-white/65">Threat Focus: {threat}</p>
              </div>
              <button
                onClick={onClose}
                className="rounded-lg border border-white/15 bg-white/5 p-2 text-white/70 transition-colors hover:bg-white/10 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-5">
              <SmallMetric label="Severity" value={style.label} className={style.text} />
              <SmallMetric label="Risk Score" value={`${finding.risk_score.toFixed(1)} / 10`} />
              <SmallMetric label="Attack Type" value={finding.attack_type || "Unknown"} />
              <SmallMetric label="Exploitability" value={exploitability(finding.risk_score)} />
              <SmallMetric label="Protocol" value={intel.protocol} />
            </div>
          </header>

          <div className="flex-1 overflow-y-auto px-5 py-4">
            <div className="grid gap-3">
              <section className="rounded-xl border border-cyan-400/25 bg-cyan-500/10 p-4">
                <div className="mb-2 flex items-center gap-2">
                  <Calculator className="h-4 w-4 text-cyan-300" />
                  <h3 className="text-sm font-semibold text-white">Risk Score Calculation</h3>
                </div>
                <div className="grid gap-2 text-sm md:grid-cols-2">
                  <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2"><span className="text-white/55">Method:</span> <span className="text-white">{calculation.source_method || "hybrid/fallback"}</span></div>
                  <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2"><span className="text-white/55">Heuristic Score:</span> <span className="text-white">{calculation.heuristic_score ?? "N/A"}</span></div>
                  <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2"><span className="text-white/55">CVSS Score:</span> <span className="text-white">{calculation.cvss_score ?? "N/A"}</span></div>
                  <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2"><span className="text-white/55">Base Score:</span> <span className="text-white">{(calculation.base_score ?? finding.risk_score).toFixed ? (calculation.base_score ?? finding.risk_score).toFixed(2) : (calculation.base_score ?? finding.risk_score)}</span></div>
                  <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2"><span className="text-white/55">Port Weight:</span> <span className="text-white">{calculation.port_weight ?? "1.00"}</span></div>
                  <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2"><span className="text-white/55">Final Score:</span> <span className="font-semibold text-cyan-100">{finding.risk_score.toFixed(2)} / 10</span></div>
                </div>
                <p className="mt-2 font-mono text-xs text-cyan-100/80">{calculation.base_formula || "base_score = 0.4 * heuristic + 0.6 * CVSS (when both are available)"}</p>
                <p className="mt-1 font-mono text-xs text-cyan-100/80">{calculation.formula || "final_score = min(10, base_score * port_weight)"}</p>
              </section>

              <section className={`rounded-xl border ${style.border} ${style.bg} p-4`}>
                <div className="mb-2 flex items-center gap-2">
                  <AlertOctagon className={`h-4 w-4 ${style.text}`} />
                  <h3 className="text-sm font-semibold text-white">Cause and Impact</h3>
                </div>
                <div className="grid gap-3 md:grid-cols-2">
                  <div className="rounded-lg border border-white/10 bg-black/20 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-white/45">Cause</p>
                    <p className="mt-1 text-sm leading-6 text-white/85">{cause}</p>
                  </div>
                  <div className="rounded-lg border border-white/10 bg-black/20 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-white/45">Impact</p>
                    <p className="mt-1 text-sm leading-6 text-white/85">{impact}</p>
                  </div>
                </div>
              </section>

              <section className="rounded-xl border border-white/10 bg-black/20 p-4">
                <div className="mb-2 flex items-center gap-2">
                  <Binary className="h-4 w-4 text-cyan-300" />
                  <h3 className="text-sm font-semibold text-white">Technical Details</h3>
                </div>
                <div className="grid gap-2 text-sm md:grid-cols-2">
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2"><span className="text-white/55">Port:</span> <span className="font-mono text-white">{finding.port}</span></div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2"><span className="text-white/55">Service:</span> <span className="font-mono text-white">{finding.service}</span></div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2"><span className="text-white/55">Protocol Family:</span> <span className="text-white">{intel.protocol}</span></div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2"><span className="text-white/55">Likely Abuse:</span> <span className="text-white">{intel.commonAbuse}</span></div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2"><span className="text-white/55">Mapped CVE:</span> <span className="font-mono text-white">{finding.cve || "None mapped"}</span></div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2"><span className="text-white/55">Threat Label:</span> <span className="text-white">{threat}</span></div>
                </div>
              </section>

              <section className="rounded-xl border border-white/10 bg-black/20 p-4">
                <div className="mb-2 flex items-center gap-2">
                  <Swords className="h-4 w-4 text-orange-300" />
                  <h3 className="text-sm font-semibold text-white">Likely Attack Flow For This Port</h3>
                </div>
                <div className="grid gap-2 md:grid-cols-3">
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-sm text-white/80">1. Recon: attacker discovers port {finding.port} open during host scan.</div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-sm text-white/80">2. Probe: service fingerprinting identifies {finding.service} and tests {finding.attack_type || "service-specific"} techniques.</div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-sm text-white/80">3. Exploit path: {finding.cve ? `known exploit attempts against ${finding.cve}.` : "misconfiguration, weak auth, or protocol weakness leveraged."}</div>
                </div>
              </section>

              <section className="rounded-xl border border-white/10 bg-black/20 p-4">
                <div className="mb-2 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-emerald-300" />
                  <h3 className="text-sm font-semibold text-white">Immediate Defenses</h3>
                </div>
                <div className="grid gap-2 md:grid-cols-3">
                  {intel.checks.map((check, index) => (
                    <div key={index} className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-sm text-white/85">
                      {check}
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-xl border border-white/10 bg-black/20 p-4">
                <div className="mb-2 flex items-center gap-2">
                  <Wrench className="h-4 w-4 text-blue-300" />
                  <h3 className="text-sm font-semibold text-white">Reference</h3>
                </div>
                {finding.cve ? (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-sm text-blue-300 underline hover:text-blue-200"
                  >
                    {finding.cve}
                  </a>
                ) : (
                  <p className="text-sm text-white/65">No direct CVE mapped for this open-port finding.</p>
                )}
              </section>
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}
