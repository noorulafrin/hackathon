import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Terminal,
  Activity,
  ArrowRight,
  Database,
  Cpu,
} from 'lucide-react';
import { SecurityAlert } from '../types/cyber.ts';

interface EvidenceModalProps {
  alert: SecurityAlert | null;
  onClose: () => void;
  onUpdateStatus: (alertId: string, status: 'New' | 'Reviewed' | 'Resolved') => Promise<void>;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({
  alert,
  onClose,
  onUpdateStatus,
}) => {
  const [showRawJson, setShowRawJson] = useState(false);
  const [updating, setUpdating] = useState(false);

  if (!alert) return null;

  const handleStatusChange = async (newStatus: 'New' | 'Reviewed' | 'Resolved') => {
    try {
      setUpdating(true);
      await onUpdateStatus(alert.id, newStatus);
    } finally {
      setUpdating(false);
    }
  };

  const getSeverityBadge = (severity: string, risk: number) => {
    if (severity === 'Malicious') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold bg-red-950/80 text-red-300 border border-red-500/50">
          <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
          MALICIOUS ({risk}/100)
        </span>
      );
    }
    if (severity === 'Suspicious') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-500/50">
          <Activity className="w-3.5 h-3.5 text-amber-400" />
          SUSPICIOUS ({risk}/100)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-500/50">
        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
        NORMAL ({risk}/100)
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-lg shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-800 rounded text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold text-slate-100">
                  {alert.id}
                </span>
                {alert.is_demo && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-500/30">
                    DEMO DATA
                  </span>
                )}
                {alert.policy_breach && (
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-500/50 animate-pulse">
                    POLICY BREACH DETECTED
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
                <Clock className="w-3 h-3 text-slate-500" />
                <span className="font-mono">{new Date(alert.timestamp).toLocaleString()}</span>
                <span>·</span>
                <span>Model: {alert.model_version}</span>
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-md transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 text-xs">
          {/* Top Key Metrics Row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-950/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[11px] mb-1">Threat Category</div>
              <div className="text-sm font-semibold text-slate-100">{alert.threat_category}</div>
              <div className="text-[11px] text-cyan-400 font-mono mt-0.5">
                {alert.confidence_pct}% Classifier Confidence
              </div>
            </div>

            <div className="p-3 bg-slate-950/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[11px] mb-1">Risk Score</div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold font-mono text-slate-100">
                  {alert.risk_score}
                </span>
                {getSeverityBadge(alert.severity, alert.risk_score)}
              </div>
            </div>

            <div className="p-3 bg-slate-950/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[11px] mb-1">Isolation Anomaly</div>
              <div className="text-sm font-semibold font-mono text-slate-100">
                {alert.anomaly_score} / 100
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {alert.anomaly_score >= 50 ? 'Statistically Anomalous' : 'Nominal Baseline'}
              </div>
            </div>

            <div className="p-3 bg-slate-950/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[11px] mb-1">Triage Status</div>
              <div className="text-sm font-semibold text-slate-100">{alert.status}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Current Analyst Workflow
              </div>
            </div>
          </div>

          {/* Network Endpoint Vector */}
          <div className="p-3 bg-slate-950/40 rounded border border-slate-800 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-sans">Source Endpoint:</span>
              <span className="text-cyan-400 font-bold">{alert.source_ip}</span>
              <span className="text-slate-500">:{alert.src_port}</span>
            </div>
            <ArrowRight className="w-4 h-4 text-slate-600" />
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-sans">Destination Endpoint:</span>
              <span className="text-amber-400 font-bold">{alert.dest_ip}</span>
              <span className="text-slate-500">:{alert.dest_port}</span>
              <span className="text-slate-500">({alert.protocol})</span>
            </div>
          </div>

          {/* EXPLAINABLE EVIDENCE SECTION (MANDATORY REQUIREMENT) */}
          <div className="p-4 bg-slate-950/80 rounded border border-cyan-500/30 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs tracking-wide uppercase">
                <Terminal className="w-4 h-4" />
                Explainable Security Evidence
              </div>
              <span className="text-[11px] text-slate-400">
                Feature Engine & Isolation Forest Findings
              </span>
            </div>
            <div className="space-y-2">
              {alert.evidence_features && alert.evidence_features.length > 0 ? (
                alert.evidence_features.map((stmt, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 text-slate-200 text-xs">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                    <span className="leading-relaxed font-sans">{stmt}</span>
                  </div>
                ))
              ) : (
                <div className="text-slate-400">No abnormal behavioral evidence recorded.</div>
              )}
            </div>
          </div>

          {/* RECOMMENDED ACTION */}
          <div className="p-4 bg-slate-950/80 rounded border border-amber-500/30 space-y-2">
            <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs tracking-wide uppercase">
              <ShieldAlert className="w-4 h-4" />
              Recommended SOC Action
            </div>
            <p className="text-slate-200 text-xs leading-relaxed font-sans">
              {alert.recommended_action}
            </p>
          </div>

          {/* Probabilities Distribution */}
          {alert.probabilities && (
            <div className="p-4 bg-slate-950/40 rounded border border-slate-800 space-y-2">
              <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Multi-Class Threat Probabilities</span>
                <span className="text-slate-500 font-mono text-[11px]">Softmax Distribution</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {Object.entries(alert.probabilities).map(([threatName, prob]) => (
                  <div
                    key={threatName}
                    className={`p-2 rounded border ${
                      threatName === alert.threat_category
                        ? 'border-cyan-500/50 bg-cyan-950/30 text-cyan-300'
                        : 'border-slate-800/80 bg-slate-950 text-slate-400'
                    }`}
                  >
                    <div className="flex justify-between text-[11px]">
                      <span>{threatName}</span>
                      <span className="font-mono font-bold">{prob}%</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1 rounded mt-1.5 overflow-hidden">
                      <div
                        className={`h-full ${threatName === alert.threat_category ? 'bg-cyan-400' : 'bg-slate-600'}`}
                        style={{ width: `${prob}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Behavioral Feature Measurements */}
          {alert.behavioral_features && (
            <div className="p-4 bg-slate-950/40 rounded border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-300">
                <span className="flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-slate-400" />
                  Sliding Window Behavioral Features ({alert.behavioral_features.window_seconds}s)
                </span>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
                <div className="p-2 bg-slate-900 rounded border border-slate-800">
                  <div className="text-slate-500">Unique Dest Ports</div>
                  <div className="font-mono text-slate-200 font-bold">
                    {alert.behavioral_features.unique_dest_port_count}
                  </div>
                </div>
                <div className="p-2 bg-slate-900 rounded border border-slate-800">
                  <div className="text-slate-500">Failed Logins</div>
                  <div className="font-mono text-slate-200 font-bold">
                    {alert.behavioral_features.failed_login_count}
                  </div>
                </div>
                <div className="p-2 bg-slate-900 rounded border border-slate-800">
                  <div className="text-slate-500">Bytes Sent</div>
                  <div className="font-mono text-slate-200 font-bold">
                    {(alert.behavioral_features.bytes_sent / 1024).toFixed(1)} KB
                  </div>
                </div>
                <div className="p-2 bg-slate-900 rounded border border-slate-800">
                  <div className="text-slate-500">Flow Frequency</div>
                  <div className="font-mono text-slate-200 font-bold">
                    {alert.behavioral_features.connection_rate_per_sec}/sec
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Raw Telemetry JSON Toggle */}
          <div className="border border-slate-800 rounded overflow-hidden">
            <button
              onClick={() => setShowRawJson(!showRawJson)}
              className="w-full px-4 py-2 bg-slate-950 text-left text-xs font-medium text-slate-400 hover:text-slate-200 flex items-center justify-between"
            >
              <span className="flex items-center gap-2">
                <Database className="w-3.5 h-3.5" />
                Raw Telemetry Payload & Internal State
              </span>
              <span className="text-[11px] font-mono text-cyan-400">
                {showRawJson ? 'Hide Payload' : 'View Payload'}
              </span>
            </button>
            {showRawJson && (
              <pre className="p-4 bg-slate-950 font-mono text-[11px] text-slate-300 overflow-x-auto border-t border-slate-800">
                {JSON.stringify(
                  {
                    raw_telemetry: alert.raw_telemetry,
                    behavioral_features: alert.behavioral_features,
                    probabilities: alert.probabilities,
                  },
                  null,
                  2
                )}
              </pre>
            )}
          </div>
        </div>

        {/* Modal Footer / Workflow Action */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="text-xs text-slate-400">
            Current Status: <span className="font-semibold text-slate-200">{alert.status}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleStatusChange('Reviewed')}
              disabled={updating || alert.status === 'Reviewed'}
              className="px-3 py-1.5 text-xs font-medium rounded border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700 disabled:opacity-50 transition-colors"
            >
              Mark Reviewed
            </button>
            <button
              onClick={() => handleStatusChange('Resolved')}
              disabled={updating || alert.status === 'Resolved'}
              className="px-3 py-1.5 text-xs font-medium rounded border border-emerald-600/50 bg-emerald-950/80 text-emerald-300 hover:bg-emerald-900 disabled:opacity-50 transition-colors"
            >
              Mark Resolved
            </button>
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 text-xs font-medium rounded bg-slate-700 text-slate-100 hover:bg-slate-600 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
