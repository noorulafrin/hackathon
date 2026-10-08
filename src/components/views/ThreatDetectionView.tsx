import React, { useState } from 'react';
import {
  Activity,
  Cpu,
  Layers,
  ShieldAlert,
  Terminal,
  Zap,
  ArrowRight,
  TrendingUp,
} from 'lucide-react';
import { SecurityAlert } from '../../types/cyber.ts';

interface ThreatDetectionViewProps {
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
}

export const ThreatDetectionView: React.FC<ThreatDetectionViewProps> = ({
  alerts,
  onSelectAlert,
}) => {
  const [selectedAlertId, setSelectedAlertId] = useState<string>(alerts[0]?.id || '');
  const activeAlert = alerts.find((a) => a.id === selectedAlertId) || alerts[0];

  const pipelineStages = [
    {
      step: '01',
      title: 'Telemetry Ingestion',
      desc: 'Validates RFC IP syntax, port ranges (0-65535), protocols, and normalizes flow timestamps.',
      status: 'Active',
    },
    {
      step: '02',
      title: 'Behavioral Feature Engine',
      desc: 'Extracts sliding time window metrics: destination diversity, port fan-out, login failure ratios, and egress volume.',
      status: 'Calibrated',
    },
    {
      step: '03',
      title: 'Anomaly Detection Layer',
      desc: 'Isolation Forest partitions high-dimensional behavioral space to measure tree isolation depth and statistical deviations.',
      status: 'Online',
    },
    {
      step: '04',
      title: 'Threat Classification',
      desc: 'Multi-class classifier calculates calibrated softmax probability vector across all 6 threat archetypes.',
      status: 'Online',
    },
    {
      step: '05',
      title: 'Deterministic Risk Scorer',
      desc: 'Applies weighted combination of anomaly score, class confidence, and security evidence to calculate transparent 0–100 score.',
      status: 'Deterministic',
    },
    {
      step: '06',
      title: 'Evidence & Policy Enforcement',
      desc: 'Generates explainable quantitative sentences and evaluates against maximum risk threshold for breach flags.',
      status: 'Enforced',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Threat Detection Engine & Feature Inspection
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Transparent end-to-end pipeline inspection from raw telemetry to explainable threat decision.
          </p>
        </div>
      </div>

      {/* 6-Stage Pipeline Architecture Ribbon */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="text-xs font-semibold text-slate-200 mb-3 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            Detection Pipeline Workflow
          </span>
          <span className="text-[11px] font-mono text-cyan-400">SentinelCore Engine v2.4</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-3">
          {pipelineStages.map((st) => (
            <div
              key={st.step}
              className="p-3 bg-slate-950 rounded border border-slate-800/80 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="font-mono text-cyan-400 font-bold">{st.step}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 bg-slate-900 text-slate-400 rounded">
                    {st.status}
                  </span>
                </div>
                <h4 className="text-xs font-semibold text-slate-200 leading-snug">{st.title}</h4>
                <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">{st.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Investigation Split: Alert Selector + Feature Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Alerts Selector (4 cols) */}
        <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-col max-h-[640px]">
          <div className="p-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">Select Threat Event</span>
            <span className="text-[11px] text-slate-500 font-mono">
              {alerts.length} Events
            </span>
          </div>
          <div className="p-2 space-y-1.5 overflow-y-auto flex-1">
            {alerts.slice(0, 30).map((a) => {
              const isSelected = activeAlert && activeAlert.id === a.id;
              return (
                <button
                  key={a.id}
                  onClick={() => setSelectedAlertId(a.id)}
                  className={`w-full text-left p-2.5 rounded text-xs transition-colors border ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-500/50 text-slate-100 shadow-sm'
                      : 'bg-slate-950/60 border-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[11px] text-cyan-300 font-medium">{a.id}</span>
                    <span
                      className={`font-mono font-bold text-[11px] px-1.5 py-0.5 rounded ${
                        a.risk_score >= 71
                          ? 'bg-red-950 text-red-300'
                          : a.risk_score >= 31
                          ? 'bg-amber-950 text-amber-300'
                          : 'bg-emerald-950 text-emerald-300'
                      }`}
                    >
                      Score: {a.risk_score}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-[11px]">
                    <span className="text-slate-300 font-medium">{a.threat_category}</span>
                    <span className="font-mono text-slate-500">{a.source_ip}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Active Event Deep Inspection (8 cols) */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-5">
          {activeAlert ? (
            <>
              {/* Event Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-100 font-mono">
                      {activeAlert.id}
                    </h3>
                    {activeAlert.policy_breach && (
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-500/50">
                        POLICY BREACH
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    Detected: <span className="font-mono">{new Date(activeAlert.timestamp).toLocaleString()}</span>
                  </div>
                </div>

                <button
                  onClick={() => onSelectAlert(activeAlert)}
                  className="px-3 py-1.5 text-xs font-semibold bg-cyan-400 text-slate-950 hover:bg-cyan-300 rounded shadow-sm transition-colors flex items-center gap-1.5 self-start sm:self-auto"
                >
                  <span>Full Evidence View</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Behavioral Feature Vector Table */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-2 mb-2">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  Behavioral Engine Feature Vector ({activeAlert.behavioral_features?.window_seconds || 60}s Sliding Window)
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
                  <div className="p-3 bg-slate-950 rounded border border-slate-800">
                    <span className="text-[11px] text-slate-400 block">Unique Dest Ports</span>
                    <span className="font-mono text-base font-bold text-cyan-400">
                      {activeAlert.behavioral_features?.unique_dest_port_count}
                    </span>
                    <span className="text-[10px] text-slate-500 block">Baseline: 1–3</span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded border border-slate-800">
                    <span className="text-[11px] text-slate-400 block">Failed Logins</span>
                    <span className="font-mono text-base font-bold text-red-400">
                      {activeAlert.behavioral_features?.failed_login_count}
                    </span>
                    <span className="text-[10px] text-slate-500 block">
                      Fail ratio: {(activeAlert.behavioral_features?.auth_fail_ratio * 100).toFixed(0)}%
                    </span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded border border-slate-800">
                    <span className="text-[11px] text-slate-400 block">Bytes Sent</span>
                    <span className="font-mono text-base font-bold text-purple-400">
                      {((activeAlert.behavioral_features?.bytes_sent || 0) / (1024 * 1024)).toFixed(1)} MB
                    </span>
                    <span className="text-[10px] text-slate-500 block">Outbound egress</span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded border border-slate-800">
                    <span className="text-[11px] text-slate-400 block">Internal Fan-Out</span>
                    <span className="font-mono text-base font-bold text-orange-400">
                      {activeAlert.behavioral_features?.unique_dest_count}
                    </span>
                    <span className="text-[10px] text-slate-500 block">Distinct peers</span>
                  </div>
                </div>
              </div>

              {/* Anomaly & Risk Breakdown */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Isolation Forest Scoring */}
                <div className="p-3.5 bg-slate-950 rounded border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <TrendingUp className="w-3.5 h-3.5 text-cyan-400" />
                      Isolation Forest Anomaly Score
                    </span>
                    <span className="font-mono font-bold text-cyan-300">
                      {activeAlert.anomaly_score}/100
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        activeAlert.anomaly_score >= 70
                          ? 'bg-red-400'
                          : activeAlert.anomaly_score >= 40
                          ? 'bg-amber-400'
                          : 'bg-emerald-400'
                      }`}
                      style={{ width: `${activeAlert.anomaly_score}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Statistical anomaly score calculated using tree partitioning path length against baseline network distributions.
                  </p>
                </div>

                {/* Deterministic Risk Breakdown */}
                <div className="p-3.5 bg-slate-950 rounded border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                      Deterministic Risk Score
                    </span>
                    <span className="font-mono font-bold text-amber-300">
                      {activeAlert.risk_score}/100
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        activeAlert.risk_score >= 71
                          ? 'bg-red-400'
                          : activeAlert.risk_score >= 31
                          ? 'bg-amber-400'
                          : 'bg-emerald-400'
                      }`}
                      style={{ width: `${activeAlert.risk_score}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Severity band: <strong className="text-slate-200">{activeAlert.severity}</strong> (0-30 Normal · 31-70 Suspicious · 71-100 Malicious).
                  </p>
                </div>
              </div>

              {/* Plain English Evidence Explanation */}
              <div className="p-4 bg-slate-950 rounded border border-cyan-500/30 space-y-2">
                <div className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  Sentinel Generated Evidence Narrative
                </div>
                <div className="space-y-1.5 text-xs text-slate-200">
                  {activeAlert.evidence_features.map((e, idx) => (
                    <div key={idx} className="flex items-start gap-2">
                      <span className="text-cyan-400">›</span>
                      <span>{e}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="text-center py-12 text-slate-500 text-xs">
              No alerts available to inspect. Run the demo simulation or ingest telemetry to view live detection states.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
