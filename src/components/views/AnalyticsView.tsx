import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  CartesianGrid,
} from 'recharts';
import { SOCAnalytics } from '../../types/cyber.ts';
import { Activity, ShieldAlert, TrendingUp, Radio } from 'lucide-react';

interface AnalyticsViewProps {
  analytics: SOCAnalytics | null;
}

const THREAT_COLORS: Record<string, string> = {
  'Port Scan': '#f59e0b',
  'Brute Force': '#ef4444',
  'Data Exfiltration': '#a855f7',
  'Lateral Movement': '#f97316',
  'Suspicious / Unknown Anomaly': '#06b6d4',
  Normal: '#10b981',
};

export const AnalyticsView: React.FC<AnalyticsViewProps> = ({ analytics }) => {
  if (!analytics) {
    return (
      <div className="p-8 text-center text-slate-500 text-xs">
        Loading analytics telemetry...
      </div>
    );
  }

  const threatData = analytics.threat_distribution.map((t) => ({
    name: t.category,
    count: t.count,
    fill: THREAT_COLORS[t.category] || '#06b6d4',
  }));

  const riskData = analytics.risk_distribution.map((r) => ({
    name: r.band,
    count: r.count,
    color: r.color,
  }));

  const timelineData = analytics.timeline || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            SOC Cyber Threat Analytics & Telemetry Metrics
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Aggregated intelligence patterns across anomalous host endpoints and attack classifications.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
          <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>Live Sentinel Stream</span>
        </div>
      </div>

      {/* Row 1: Threat Distribution & Risk Bands */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Threat Distribution Chart */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Alerts by Threat Classification
            </span>
            <span className="text-[11px] font-mono text-slate-400">Class Volume</span>
          </div>

          <div className="h-64 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatData} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="name"
                  stroke="#64748b"
                  fontSize={10}
                  interval={0}
                  angle={-15}
                  textAnchor="end"
                />
                <YAxis stroke="#64748b" fontSize={10} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#020617',
                    borderColor: '#334155',
                    fontSize: '11px',
                    borderRadius: '6px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {threatData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Bands Distribution Donut */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" />
              Risk Severity Spectrum Distribution
            </span>
            <span className="text-[11px] font-mono text-slate-400">0–100 Bands</span>
          </div>

          <div className="h-64 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  label={({ name, percent }: { name?: string; percent?: number }) =>
                    name && percent !== undefined ? `${name.split(' ')[0]} (${(percent * 100).toFixed(0)}%)` : ''
                  }
                  labelLine={false}
                >
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-risk-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#020617',
                    borderColor: '#334155',
                    fontSize: '11px',
                    borderRadius: '6px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 2: Timeline of Events Over Time */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyan-400" />
            Security Events & Attack Velocity Timeline
          </span>
          <span className="text-[11px] font-mono text-slate-400">Burst Activity</span>
        </div>

        <div className="h-64 w-full pt-2">
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} />
                <YAxis stroke="#64748b" fontSize={10} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#020617',
                    borderColor: '#334155',
                    fontSize: '11px',
                    borderRadius: '6px',
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="malicious"
                  stroke="#ef4444"
                  strokeWidth={2}
                  name="Malicious"
                  dot={{ r: 3 }}
                />
                <Line
                  type="monotone"
                  dataKey="suspicious"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  name="Suspicious"
                  dot={{ r: 3 }}
                />
                <Line
                  type="monotone"
                  dataKey="normal"
                  stroke="#10b981"
                  strokeWidth={2}
                  name="Normal"
                  dot={{ r: 3 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-slate-500 text-xs">
              No timeline buckets aggregated yet.
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Top Attacking Source Endpoints & Targeted Internal Destinations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="text-xs font-semibold text-slate-200 mb-3">
            Top Attacking Source IP Addresses
          </div>
          <div className="space-y-2">
            {analytics.top_sources.map((s) => (
              <div
                key={s.ip}
                className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
              >
                <div>
                  <div className="font-mono text-cyan-300 font-semibold">{s.ip}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Threat: {s.dominant_threat} · {s.event_count} flows
                  </div>
                </div>
                <div className="font-mono font-bold text-red-400 text-xs bg-red-950/60 px-2 py-1 rounded border border-red-500/30">
                  Risk: {s.max_risk}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="text-xs font-semibold text-slate-200 mb-3">
            Top Targeted Destination Endpoints
          </div>
          <div className="space-y-2">
            {analytics.top_destinations.map((d) => (
              <div
                key={d.ip}
                className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
              >
                <div>
                  <div className="font-mono text-amber-300 font-semibold">{d.ip}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Internal Asset / External Peer
                  </div>
                </div>
                <div className="font-mono text-slate-300 text-xs bg-slate-900 px-2 py-1 rounded border border-slate-800">
                  {d.event_count} incoming connections
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
