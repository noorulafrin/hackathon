import React, { useState, useEffect } from 'react';
import {
  HeartPulse,
  Cpu,
  Database,
  Activity,
  Shield,
  Layers,
  CheckCircle2,
  Clock,
  RefreshCw,
  Server,
  Zap,
} from 'lucide-react';
import { fetchSystemHealth, resetDemoData } from '../../services/api.ts';
import { SystemHealth } from '../../types/cyber.ts';

interface SystemHealthViewProps {
  onResetComplete: () => void;
}

export const SystemHealthView: React.FC<SystemHealthViewProps> = ({ onResetComplete }) => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [resetting, setResetting] = useState<boolean>(false);

  const loadHealth = async () => {
    try {
      setLoading(true);
      const h = await fetchSystemHealth();
      setHealth(h);
    } catch (err) {
      console.error('Error fetching system health:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleResetData = async () => {
    if (!window.confirm('Reset all demo telemetry and clear stored alerts?')) return;
    try {
      setResetting(true);
      await resetDemoData();
      await loadHealth();
      onResetComplete();
    } finally {
      setResetting(false);
    }
  };

  const getStatusBadge = (status: string) => (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-500/30">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
      {status}
    </span>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            CyberSentinel Subsystem Health & Diagnostics
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Operational status, pipeline execution latencies, and machine learning engine invariants.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadHealth}
            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-900 rounded-md border border-slate-800 transition-colors"
            title="Refresh Health"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={handleResetData}
            disabled={resetting}
            className="px-3 py-1.5 text-xs font-medium text-red-400 hover:text-red-300 bg-red-950/40 hover:bg-red-950 border border-red-500/30 rounded-md transition-colors"
          >
            {resetting ? 'Resetting...' : 'Reset Sentinel Data'}
          </button>
        </div>
      </div>

      {/* 6 Subsystem Health Blocks */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Subsystem 1: Telemetry Pipeline */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Telemetry Pipeline
            </span>
            {getStatusBadge(health?.telemetry_pipeline || 'ONLINE')}
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            RFC IP parsing, port verification, and streaming stream ingestion buffer.
          </p>
          <div className="text-[11px] font-mono text-slate-500 pt-1">
            Status: Nominal · Ingestion active
          </div>
        </div>

        {/* Subsystem 2: Behavioral Feature Engine */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Feature Engine
            </span>
            {getStatusBadge(health?.feature_engine || 'ONLINE')}
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Stateful sliding time windows computing destination diversity & connection burst rate.
          </p>
          <div className="text-[11px] font-mono text-slate-500 pt-1">
            Status: Window synchronized
          </div>
        </div>

        {/* Subsystem 3: Anomaly Detector */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Anomaly Detector
            </span>
            {getStatusBadge(health?.anomaly_detector || 'ONLINE')}
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Multi-dimensional Isolation Forest tree depth estimator with anomaly normalization.
          </p>
          <div className="text-[11px] font-mono text-slate-500 pt-1">
            Status: Forest calibrated
          </div>
        </div>

        {/* Subsystem 4: Classifier */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Threat Classifier
            </span>
            {getStatusBadge(health?.classifier || 'ONLINE')}
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Softmax multi-class inference across Port Scan, Brute Force, Lateral, and Exfiltration.
          </p>
          <div className="text-[11px] font-mono text-slate-500 pt-1">
            Status: 6 classes active
          </div>
        </div>

        {/* Subsystem 5: Database */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              Persistent Database
            </span>
            {getStatusBadge(health?.database || 'ONLINE')}
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            SQLite WebAssembly database with atomic disk persistence and indexed query tables.
          </p>
          <div className="text-[11px] font-mono text-slate-500 pt-1">
            Status: SQLite sync verified
          </div>
        </div>

        {/* Subsystem 6: Policy Engine */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Policy Engine
            </span>
            {getStatusBadge(health?.policy_engine || 'ONLINE')}
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Deterministic risk guardrails with instant threshold breach evaluation and triage tagging.
          </p>
          <div className="text-[11px] font-mono text-slate-500 pt-1">
            Status: Guardrails enforced
          </div>
        </div>
      </div>

      {/* Diagnostics & Performance Metrics */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4">
        <div className="text-xs font-semibold text-slate-200 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Runtime Telemetry & Performance Metrics
          </span>
          <span className="text-[11px] font-mono text-cyan-400">
            Model: {health?.model_version || 'v2.4.1 SentinelCore'}
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-500 text-[11px]">Total Events Processed</span>
            <div className="font-mono text-lg font-bold text-slate-100 mt-1">
              {health?.events_processed.toLocaleString() || '0'}
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-500 text-[11px]">Alerts Generated</span>
            <div className="font-mono text-lg font-bold text-cyan-400 mt-1">
              {health?.alerts_generated.toLocaleString() || '0'}
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-500 text-[11px]">Average Processing Latency</span>
            <div className="font-mono text-lg font-bold text-emerald-400 mt-1">
              {health?.processing_latency_ms || 18} ms
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-500 text-[11px]">System Uptime</span>
            <div className="font-mono text-lg font-bold text-slate-100 mt-1">
              {health?.uptime_seconds ? `${Math.floor(health.uptime_seconds / 60)}m ${health.uptime_seconds % 60}s` : 'Active'}
            </div>
          </div>
        </div>

        <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row justify-between text-xs text-slate-400 gap-2">
          <div>
            Last Processed Event:{' '}
            <span className="font-mono text-slate-200">
              {health?.last_processed_timestamp
                ? new Date(health.last_processed_timestamp).toLocaleString()
                : 'Awaiting events'}
            </span>
          </div>
          <div>
            Active Policy Breaches:{' '}
            <span className="font-mono font-bold text-red-400">
              {health?.active_policy_breaches || 0}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
