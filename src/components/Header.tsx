import React from 'react';
import { Shield, Play, AlertTriangle, RefreshCw, UserCheck } from 'lucide-react';

interface HeaderProps {
  lastUpdated: Date;
  onRefresh: () => void;
  onRunDemo: () => void;
  isDemoRunning: boolean;
  policyBreachesCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  lastUpdated,
  onRefresh,
  onRunDemo,
  isDemoRunning,
  policyBreachesCount,
}) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/90 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Zone 1: Brand Title */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950/50">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <span className="font-bold text-base tracking-tight text-slate-100 uppercase">
              CyberSentinel
            </span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-500/30">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              ONLINE
            </span>
            {policyBreachesCount > 0 && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-red-950/80 text-red-400 border border-red-500/50 animate-pulse">
                <AlertTriangle className="w-3 h-3 text-red-400" />
                {policyBreachesCount} BREACH{policyBreachesCount > 1 ? 'ES' : ''}
              </span>
            )}
          </div>
          <span className="text-[11px] text-slate-400 hidden sm:inline">
            Intelligent Cyber Threat & Network Anomaly Detection
          </span>
        </div>
      </div>

      {/* Zone 2: Middle Meta / Ticker */}
      <div className="hidden lg:flex items-center gap-4 text-xs text-slate-400">
        <span className="flex items-center gap-1.5">
          <span className="text-slate-500">Updated:</span>
          <span className="font-mono text-slate-300 tabular-nums">
            {lastUpdated.toLocaleTimeString()}
          </span>
        </span>
        <span className="text-slate-700">|</span>
        <span className="flex items-center gap-1.5">
          <span className="text-slate-500">Engine:</span>
          <span className="font-mono text-cyan-400">SentinelCore v2.4</span>
        </span>
      </div>

      {/* Zone 3: Primary Actions & Profile */}
      <div className="flex items-center gap-3">
        <button
          onClick={onRefresh}
          title="Refresh Data"
          className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-900 rounded-md border border-slate-800 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

        <button
          onClick={onRunDemo}
          disabled={isDemoRunning}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed rounded-md shadow-sm shadow-cyan-900/30 transition-colors whitespace-nowrap"
        >
          <Play className={`w-3.5 h-3.5 fill-current ${isDemoRunning ? 'animate-spin' : ''}`} />
          <span>{isDemoRunning ? 'Replaying...' : 'Run Demo Simulation'}</span>
        </button>

        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
            <UserCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="hidden xl:flex flex-col text-left">
            <span className="text-xs font-medium text-slate-200 leading-tight">SOC Operator</span>
            <span className="text-[10px] text-slate-400 font-mono">L3 Lead Analyst</span>
          </div>
        </div>
      </div>
    </header>
  );
};
