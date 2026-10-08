import React, { useState, useEffect } from 'react';
import {
  FileText,
  Search,
  Download,
  Filter,
  CheckCircle2,
  Database,
  Terminal,
  X,
} from 'lucide-react';
import { fetchAuditLogs } from '../../services/api.ts';
import { AuditLogEntry } from '../../types/cyber.ts';

export const AuditLogsView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const data = await fetchAuditLogs(300);
      setLogs(data);
    } catch (err) {
      console.error('Error fetching audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  const filteredLogs = logs.filter((log) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      log.id.toLowerCase().includes(q) ||
      log.alert_id.toLowerCase().includes(q) ||
      log.source_ip.toLowerCase().includes(q) ||
      log.classification.toLowerCase().includes(q) ||
      log.action_taken.toLowerCase().includes(q) ||
      log.operator.toLowerCase().includes(q)
    );
  });

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `cybersentinel_audit_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Persistent Security Audit Trail
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Immutable SQLite records of all threat classifications, scoring calculations, and operator triage actions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Audit JSON</span>
          </button>
        </div>
      </div>

      {/* Control Bar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search audit trail by IP, alert ID, action, operator..."
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="text-xs text-slate-400 font-mono">
          <span>{filteredLogs.length} Records In Storage</span>
          <span className="mx-2 text-slate-600">·</span>
          <span className="text-cyan-400">SQLite WebAssembly Database</span>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Audit ID</th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Alert ID</th>
                <th className="py-2.5 px-4">Endpoints</th>
                <th className="py-2.5 px-4">Classification</th>
                <th className="py-2.5 px-4">Action Taken</th>
                <th className="py-2.5 px-4">Operator</th>
                <th className="py-2.5 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredLogs.length > 0 ? (
                filteredLogs.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => setSelectedEntry(entry)}
                  >
                    <td className="py-2.5 px-4 font-mono text-cyan-300 whitespace-nowrap text-[11px]">
                      {entry.id}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap tabular-nums text-[11px]">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300 whitespace-nowrap text-[11px]">
                      {entry.alert_id}
                    </td>
                    <td className="py-2.5 px-4 font-mono whitespace-nowrap text-[11px]">
                      <span className="text-slate-200">{entry.source_ip}</span>
                      <span className="text-slate-600"> → </span>
                      <span className="text-slate-400">{entry.dest_ip}</span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span className="text-slate-200 font-medium">{entry.classification}</span>
                      <span className="text-slate-500 font-mono text-[11px] ml-1.5">
                        ({entry.risk_score})
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span className="font-mono text-[11px] text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/20">
                        {entry.action_taken}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap text-slate-400">
                      {entry.operator}
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEntry(entry);
                        }}
                        className="text-[11px] text-cyan-300 hover:text-cyan-200 px-2 py-1 rounded bg-slate-950 border border-slate-800"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-500 text-xs">
                    {loading ? 'Reading persistent audit database...' : 'No audit records found.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Audit Entry Inspection Modal */}
      {selectedEntry && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>Audit Entry: {selectedEntry.id}</span>
              </div>
              <button
                onClick={() => setSelectedEntry(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div className="p-2 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-500 block">Alert ID</span>
                  <span className="text-slate-200 font-bold">{selectedEntry.alert_id}</span>
                </div>
                <div className="p-2 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-500 block">Operator & Model</span>
                  <span className="text-cyan-300 font-bold">
                    {selectedEntry.operator} · {selectedEntry.model_version}
                  </span>
                </div>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                <span className="text-slate-500 block">Evidence Summary</span>
                <p className="text-slate-200 font-sans leading-relaxed">
                  {selectedEntry.evidence_summary}
                </p>
              </div>

              <div className="space-y-1">
                <span className="text-slate-500 block">Recorded Feature Values JSON</span>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto">
                  {selectedEntry.feature_values}
                </pre>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedEntry(null)}
                className="px-4 py-1.5 text-xs font-medium rounded bg-slate-800 text-slate-200 hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
