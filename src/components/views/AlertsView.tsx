import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowUpDown,
  Eye,
  CheckCircle2,
  Clock,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { SecurityAlert, AlertStatus } from '../../types/cyber.ts';

interface AlertsViewProps {
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
  onUpdateStatus: (alertId: string, status: AlertStatus) => Promise<void>;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onSelectAlert,
  onUpdateStatus,
}) => {
  const [filterCategory, setFilterCategory] = useState<string>('All');
  const [filterStatus, setFilterStatus] = useState<string>('All');
  const [sortBy, setSortBy] = useState<'risk' | 'timestamp' | 'severity'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filterOptions = [
    'All',
    'Normal',
    'Suspicious',
    'Malicious',
    'Port Scan',
    'Brute Force',
    'Lateral Movement',
    'Data Exfiltration',
  ];

  const filteredAlerts = alerts
    .filter((a) => {
      // Category or severity match
      if (filterCategory !== 'All') {
        if (['Normal', 'Suspicious', 'Malicious'].includes(filterCategory)) {
          if (a.severity !== filterCategory) return false;
        } else {
          if (a.threat_category !== filterCategory) return false;
        }
      }

      // Status match
      if (filterStatus !== 'All' && a.status !== filterStatus) return false;

      // Search match
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
    })
    .sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'risk') {
        comparison = a.risk_score - b.risk_score;
      } else if (sortBy === 'severity') {
        const orderMap: Record<string, number> = { Normal: 1, Suspicious: 2, Malicious: 3 };
        comparison = (orderMap[a.severity] || 0) - (orderMap[b.severity] || 0);
      } else {
        comparison = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      }
      return sortOrder === 'desc' ? -comparison : comparison;
    });

  const toggleSort = (field: 'risk' | 'timestamp' | 'severity') => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Alert Management & Incident Triage
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Filter, prioritize, and triage detected cyber threat anomalies with full auditability.
          </p>
        </div>
        <div className="text-xs text-slate-400 font-mono">
          Showing <span className="text-slate-200 font-bold">{filteredAlerts.length}</span> of{' '}
          {alerts.length} total alerts
        </div>
      </div>

      {/* Filter and Control Bar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
        {/* Row 1: Primary Category / Threat Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
          <span className="text-slate-400 font-medium mr-1 flex items-center gap-1 shrink-0">
            <Filter className="w-3.5 h-3.5" />
            Threat Filter:
          </span>
          {filterOptions.map((opt) => (
            <button
              key={opt}
              onClick={() => setFilterCategory(opt)}
              className={`px-2.5 py-1 rounded text-xs font-medium whitespace-nowrap transition-colors ${
                filterCategory === opt
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-950'
              }`}
            >
              {opt}
            </button>
          ))}
        </div>

        {/* Row 2: Search, Status, and Sort Controls */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by IP, ID, threat..."
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
            {/* Status Filter */}
            <div className="flex items-center gap-1 text-xs bg-slate-950 p-1 rounded border border-slate-800">
              <span className="text-slate-400 px-1 text-[11px]">Status:</span>
              {['All', 'New', 'Reviewed', 'Resolved'].map((st) => (
                <button
                  key={st}
                  onClick={() => setFilterStatus(st)}
                  className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                    filterStatus === st
                      ? 'bg-slate-800 text-cyan-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>

            {/* Sort Dropdown / Toggle */}
            <div className="flex items-center gap-1 text-xs bg-slate-950 p-1 rounded border border-slate-800">
              <span className="text-slate-400 px-1 text-[11px]">Sort:</span>
              <button
                onClick={() => toggleSort('timestamp')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium flex items-center gap-1 ${
                  sortBy === 'timestamp' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400'
                }`}
              >
                Time {sortBy === 'timestamp' && (sortOrder === 'desc' ? '↓' : '↑')}
              </button>
              <button
                onClick={() => toggleSort('risk')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium flex items-center gap-1 ${
                  sortBy === 'risk' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400'
                }`}
              >
                Risk {sortBy === 'risk' && (sortOrder === 'desc' ? '↓' : '↑')}
              </button>
              <button
                onClick={() => toggleSort('severity')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium flex items-center gap-1 ${
                  sortBy === 'severity' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400'
                }`}
              >
                Severity {sortBy === 'severity' && (sortOrder === 'desc' ? '↓' : '↑')}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Alert ID</th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Endpoints</th>
                <th className="py-2.5 px-4">Classification</th>
                <th className="py-2.5 px-4">Risk Score</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Workflow Status</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((a) => (
                  <tr
                    key={a.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectAlert(a)}
                  >
                    <td className="py-2.5 px-4 font-mono font-medium text-cyan-300 whitespace-nowrap">
                      {a.id}
                      {a.policy_breach && (
                        <span className="block text-[10px] text-red-400 font-bold">
                          [POLICY BREACH]
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap tabular-nums text-[11px]">
                      {new Date(a.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4 font-mono whitespace-nowrap text-[11px]">
                      <div className="text-cyan-300">
                        {a.source_ip}:{a.src_port}
                      </div>
                      <div className="text-slate-500">
                        → {a.dest_ip}:{a.dest_port}
                      </div>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <div className="font-semibold text-slate-200">{a.threat_category}</div>
                      <div className="text-[10px] text-cyan-400 font-mono">
                        {a.confidence_pct}% Conf.
                      </div>
                    </td>
                    <td className="py-2.5 px-4 font-mono font-bold whitespace-nowrap tabular-nums text-sm">
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
                      <span
                        className={`text-[11px] font-semibold ${
                          a.severity === 'Malicious'
                            ? 'text-red-400'
                            : a.severity === 'Suspicious'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {a.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center gap-1">
                        <select
                          value={a.status}
                          onChange={(e) =>
                            onUpdateStatus(a.id, e.target.value as AlertStatus)
                          }
                          className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-[11px] text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
                        >
                          <option value="New">New</option>
                          <option value="Reviewed">Reviewed</option>
                          <option value="Resolved">Resolved</option>
                        </select>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectAlert(a)}
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
                  <td colSpan={8} className="py-12 text-center text-slate-500 text-xs">
                    No alerts match the chosen filters.
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
