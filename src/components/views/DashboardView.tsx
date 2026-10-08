import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  CheckCircle2,
  Gauge,
  ArrowUpRight,
  Eye,
  Filter,
  Search,
} from 'lucide-react';
import { SecurityAlert, SOCAnalytics } from '../../types/cyber.ts';

interface DashboardViewProps {
  analytics: SOCAnalytics | null;
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
  onNavigateToTelemetry: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  analytics,
  alerts,
  onSelectAlert,
  onNavigateToTelemetry,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity !== 'All' && a.severity !== filterSeverity) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        a.source_ip.toLowerCase().includes(q) ||
        a.dest_ip.toLowerCase().includes(q) ||
        a.threat_category.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityPill = (severity: string, score: number) => {
    if (severity === 'Malicious') {
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-400">
          <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
          Malicious ({score})
        </span>
      );
    }
    if (severity === 'Suspicious') {
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-400">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
          Suspicious ({score})
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        Normal ({score})
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Editorial Kicker */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Security Operations Center (SOC) Console
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time telemetry ingestion, behavioral anomaly isolation, and explainable threat triage.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onNavigateToTelemetry}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-500/30 rounded-md transition-colors"
          >
            <span>+ Ingest Telemetry</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 5 Summary KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs">Total Ingested Events</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {analytics?.total_events.toLocaleString() || '0'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Validated network flows</div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs">Critical Alerts</span>
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400 tabular-nums">
            {analytics?.critical_alerts.toLocaleString() || '0'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Risk score 71 – 100</div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs">Suspicious Alerts</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 tabular-nums">
            {analytics?.suspicious_alerts.toLocaleString() || '0'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Risk score 31 – 70</div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs">Normal Events</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
            {analytics?.normal_events.toLocaleString() || '0'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Risk score 0 – 30</div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs">Average Risk Score</span>
            <Gauge className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {analytics?.average_risk_score || 0}
            <span className="text-xs font-normal text-slate-500 ml-1">/ 100</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Deterministic aggregate</div>
        </div>
      </div>

      {/* Visual Analytics Row: Threat Distribution + Risk Breakdown + Top Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Threat Distribution */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-200">Threat Category Distribution</span>
            <span className="text-[11px] text-slate-500 font-mono">Classifier Output</span>
          </div>
          <div className="space-y-2.5 flex-1 justify-center flex flex-col">
            {analytics?.threat_distribution && analytics.threat_distribution.length > 0 ? (
              analytics.threat_distribution.map((t) => {
                let barColor = 'bg-cyan-500';
                if (t.category === 'Port Scan') barColor = 'bg-amber-400';
                if (t.category === 'Brute Force') barColor = 'bg-red-400';
                if (t.category === 'Data Exfiltration') barColor = 'bg-purple-400';
                if (t.category === 'Lateral Movement') barColor = 'bg-orange-400';
                if (t.category === 'Normal') barColor = 'bg-emerald-400';

                return (
                  <div key={t.category} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-300">{t.category}</span>
                      <span className="font-mono text-slate-400 tabular-nums">
                        {t.count} ({t.percentage}%)
                      </span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${barColor} rounded-full`}
                        style={{ width: `${Math.max(4, t.percentage)}%` }}
                      />
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-xs text-slate-500 py-4 text-center">No classified events</div>
            )}
          </div>
        </div>

        {/* Risk Bands Distribution */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-200">Risk Severity Bands</span>
            <span className="text-[11px] text-slate-500 font-mono">0–100 Spectrum</span>
          </div>
          <div className="space-y-3 flex-1 flex flex-col justify-center">
            {analytics?.risk_distribution.map((band) => {
              const total = analytics.total_alerts || 1;
              const pct = Math.round((band.count / total) * 100);
              return (
                <div key={band.band} className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
                  <div className="flex justify-between items-center text-xs">
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ backgroundColor: band.color }}
                      />
                      <span className="font-medium text-slate-200">{band.band}</span>
                    </div>
                    <span className="font-mono text-slate-100 font-bold tabular-nums">
                      {band.count} ({pct}%)
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full mt-2 overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${Math.max(2, pct)}%`,
                        backgroundColor: band.color,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Attacking Source IPs */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-200">Top Anomaly Source Endpoints</span>
            <span className="text-[11px] text-slate-500 font-mono">Max Risk</span>
          </div>
          <div className="space-y-2 flex-1 overflow-y-auto">
            {analytics?.top_sources && analytics.top_sources.length > 0 ? (
              analytics.top_sources.map((src) => (
                <div
                  key={src.ip}
                  className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60 text-xs"
                >
                  <div className="flex flex-col">
                    <span className="font-mono text-cyan-300 font-semibold">{src.ip}</span>
                    <span className="text-[11px] text-slate-400">
                      {src.dominant_threat} · {src.event_count} events
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`font-mono text-xs font-bold px-2 py-0.5 rounded ${
                        src.max_risk >= 71
                          ? 'bg-red-950/80 text-red-300 border border-red-500/40'
                          : src.max_risk >= 31
                          ? 'bg-amber-950/80 text-amber-300 border border-amber-500/40'
                          : 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/40'
                      }`}
                    >
                      {src.max_risk}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs text-slate-500 py-4 text-center">No source events recorded</div>
            )}
          </div>
        </div>
      </div>

      {/* LIVE THREAT MONITORING TABLE */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {/* Table Header Controls */}
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950/60">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>Live Threat Monitoring Sentinel</span>
              <span className="text-xs font-normal text-slate-400">
                ({filteredAlerts.length} events displayed)
              </span>
            </h2>
          </div>

          <div className="flex items-center gap-2.5">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IP, alert, threat..."
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800 text-xs">
              <Filter className="w-3 h-3 text-slate-500 ml-1" />
              {['All', 'Malicious', 'Suspicious', 'Normal'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                    filterSeverity === sev
                      ? 'bg-slate-800 text-cyan-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* High-Density Data Grid */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Source IP</th>
                <th className="py-2.5 px-4">Destination IP</th>
                <th className="py-2.5 px-4">Threat Category</th>
                <th className="py-2.5 px-4">Risk Score</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.slice(0, 50).map((a) => (
                  <tr
                    key={a.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectAlert(a)}
                  >
                    <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap text-[11px] tabular-nums">
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-cyan-300 font-medium whitespace-nowrap">
                      {a.source_ip}
                      <span className="text-slate-600 font-normal">:{a.src_port}</span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300 whitespace-nowrap">
                      {a.dest_ip}
                      <span className="text-slate-600 font-normal">:{a.dest_port}</span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span className="text-slate-200 font-medium">{a.threat_category}</span>
                      {a.policy_breach && (
                        <span className="ml-2 text-[10px] font-mono text-red-400 font-semibold">
                          [BREACH]
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-mono font-bold whitespace-nowrap tabular-nums">
                      <span
                        className={
                          a.risk_score >= 71
                            ? 'text-red-400'
                            : a.risk_score >= 31
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {a.risk_score}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      {getSeverityPill(a.severity, a.risk_score)}
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span
                        className={`text-[11px] px-2 py-0.5 rounded ${
                          a.status === 'Resolved'
                            ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                            : a.status === 'Reviewed'
                            ? 'bg-blue-950/60 text-blue-400 border border-blue-500/30'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {a.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(a);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-cyan-300 hover:text-cyan-200 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-500/40 rounded transition-colors"
                      >
                        <Eye className="w-3 h-3" />
                        <span>View Evidence</span>
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 text-xs">
                    No security events match the current filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
