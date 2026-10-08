import React from 'react';
import {
  LayoutDashboard,
  FileInput,
  Activity,
  ShieldAlert,
  BarChart3,
  FileText,
  Sliders,
  HeartPulse,
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'telemetry'
  | 'detection'
  | 'alerts'
  | 'analytics'
  | 'audit'
  | 'policy'
  | 'health';

interface SidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  alertCount: number;
  breachCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  alertCount,
  breachCount,
}) => {
  const navItems = [
    { id: 'dashboard' as NavTab, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'telemetry' as NavTab, label: 'Telemetry Input', icon: FileInput },
    { id: 'detection' as NavTab, label: 'Threat Detection', icon: Activity },
    {
      id: 'alerts' as NavTab,
      label: 'Alerts',
      icon: ShieldAlert,
      badge: alertCount > 0 ? alertCount : null,
      badgeColor: breachCount > 0 ? 'bg-red-500/20 text-red-400 border border-red-500/40' : 'bg-amber-500/20 text-amber-400 border border-amber-500/40',
    },
    { id: 'analytics' as NavTab, label: 'Analytics', icon: BarChart3 },
    { id: 'audit' as NavTab, label: 'Audit Logs', icon: FileText },
    { id: 'policy' as NavTab, label: 'Security Policy', icon: Sliders },
    { id: 'health' as NavTab, label: 'System Health', icon: HeartPulse },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950 flex flex-col shrink-0 select-none">
      <div className="p-4 border-b border-slate-800/80">
        <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
          SOC Sentinel Navigation
        </div>
      </div>

      <nav className="p-2 space-y-1 flex-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-slate-800/90 text-cyan-300 shadow-sm border border-slate-700/60'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge !== null && item.badge !== undefined && (
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    item.badgeColor || 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Persistent Baseline Info */}
      <div className="p-4 border-t border-slate-800 text-xs text-slate-400 space-y-2">
        <div className="flex items-center justify-between">
          <span>Telemetry Stream</span>
          <span className="font-mono text-emerald-400 text-[11px]">Active</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Isolation Forest</span>
          <span className="font-mono text-cyan-400 text-[11px]">Calibrated</span>
        </div>
        <div className="pt-2 text-[10px] text-slate-400 font-mono">
          CYBERSENTINEL DEFENSE ENGINE
        </div>
      </div>
    </aside>
  );
};
