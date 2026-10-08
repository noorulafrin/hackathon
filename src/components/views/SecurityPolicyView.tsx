import React, { useState, useEffect } from 'react';
import {
  Sliders,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Save,
  Filter,
  Flame,
  Lock,
} from 'lucide-react';
import { fetchPolicy, updatePolicy } from '../../services/api.ts';
import { SecurityPolicy } from '../../types/cyber.ts';

interface SecurityPolicyViewProps {
  onPolicyUpdated?: () => void;
}

export const SecurityPolicyView: React.FC<SecurityPolicyViewProps> = ({ onPolicyUpdated }) => {
  const [policy, setPolicy] = useState<SecurityPolicy>({
    max_risk_threshold: 70,
    auto_prioritize_high_risk: true,
    enable_noise_filtering: true,
    enable_background_filtering: true,
    sliding_window_seconds: 60,
    auto_isolate_endpoints: false,
  });

  const [saving, setSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  useEffect(() => {
    fetchPolicy()
      .then((p) => setPolicy(p))
      .catch((err) => console.error('Failed to load policy:', err));
  }, []);

  const handleSave = async () => {
    try {
      setSaving(true);
      setSaveSuccess(false);
      const updated = await updatePolicy(policy);
      setPolicy(updated);
      setSaveSuccess(true);
      if (onPolicyUpdated) onPolicyUpdated();
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save policy:', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Security Policy & Guardrail Configuration
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure automated sentinel tripwires, maximum risk tolerance thresholds, and noise suppression rules.
          </p>
        </div>
        <div>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded shadow-md shadow-cyan-950/40 transition-colors"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Applying Policy...' : 'Save Policy Rules'}</span>
          </button>
        </div>
      </div>

      {saveSuccess && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-500/50 rounded text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>Security policy saved and immediately enforced across live telemetry pipeline.</span>
        </div>
      )}

      {/* Main Guardrail Settings Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Maximum Risk Threshold Slider */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Flame className="w-4 h-4 text-red-400" />
              Maximum Risk Threshold
            </span>
            <span className="font-mono text-base font-bold text-red-400 bg-red-950/60 px-2.5 py-0.5 rounded border border-red-500/40">
              {policy.max_risk_threshold} / 100
            </span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Events with a deterministic risk score greater than or equal to this threshold immediately trigger a{' '}
            <strong className="text-red-400">POLICY BREACH DETECTED</strong> sentinel alert and mandate analyst escalation.
          </p>

          <div className="space-y-2 pt-2">
            <input
              type="range"
              min="20"
              max="95"
              step="1"
              value={policy.max_risk_threshold}
              onChange={(e) =>
                setPolicy({ ...policy, max_risk_threshold: parseInt(e.target.value, 10) })
              }
              className="w-full accent-cyan-400 cursor-pointer h-2 bg-slate-800 rounded-lg appearance-none"
            />
            <div className="flex justify-between text-[11px] font-mono text-slate-500">
              <span>20 (Aggressive)</span>
              <span>50 (Moderate)</span>
              <span className="text-amber-400 font-bold">70 (Default)</span>
              <span>90 (Permissive)</span>
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800 flex items-center gap-3 text-xs">
            <div className="p-2 rounded bg-red-950/80 text-red-400 border border-red-500/40">
              <AlertTriangle className="w-4 h-4" />
            </div>
            <div>
              <div className="font-semibold text-slate-200">Policy Breach Sentinel Status</div>
              <div className="text-slate-400 text-[11px]">
                Scores &ge; {policy.max_risk_threshold} will be marked with persistent breach banners.
              </div>
            </div>
          </div>
        </div>

        {/* Behavioral Sliding Time Window */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Sliding Time Window Buffer
            </span>
            <span className="font-mono text-base font-bold text-cyan-400 bg-cyan-950/60 px-2.5 py-0.5 rounded border border-cyan-500/40">
              {policy.sliding_window_seconds}s
            </span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            The historical temporal buffer used to calculate behavioral features (unique ports scanned, failed login velocity, and rate of change).
          </p>

          <div className="space-y-2 pt-2">
            <input
              type="range"
              min="10"
              max="300"
              step="10"
              value={policy.sliding_window_seconds}
              onChange={(e) =>
                setPolicy({ ...policy, sliding_window_seconds: parseInt(e.target.value, 10) })
              }
              className="w-full accent-cyan-400 cursor-pointer h-2 bg-slate-800 rounded-lg appearance-none"
            />
            <div className="flex justify-between text-[11px] font-mono text-slate-500">
              <span>10s (Fast Scan)</span>
              <span className="text-cyan-400 font-bold">60s (Standard)</span>
              <span>120s</span>
              <span>300s (5 Min)</span>
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-xs text-slate-400">
            A window of <strong className="text-slate-200">{policy.sliding_window_seconds} seconds</strong> correlates up to hundreds of incoming flows per source IP.
          </div>
        </div>

        {/* Noise & Benign Filtering Toggles */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 lg:col-span-2">
          <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
            <Filter className="w-4 h-4 text-emerald-400" />
            Telemetry Noise Suppression & Workflow Governance
          </span>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
            {/* Toggle 1 */}
            <div className="p-4 bg-slate-950 rounded border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="text-xs font-semibold text-slate-200 mb-1">
                  Enable Benign Noise Filtering
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Suppresses routine DHCP (67/68), mDNS (5353), NTP (123), and SSDP broadcast traffic from generating spurious alerts.
                </p>
              </div>
              <label className="flex items-center gap-2 cursor-pointer pt-2">
                <input
                  type="checkbox"
                  checked={policy.enable_noise_filtering}
                  onChange={(e) =>
                    setPolicy({ ...policy, enable_noise_filtering: e.target.checked })
                  }
                  className="w-4 h-4 accent-cyan-400 rounded"
                />
                <span className="text-xs text-slate-300 font-medium">Active (Recommended)</span>
              </label>
            </div>

            {/* Toggle 2 */}
            <div className="p-4 bg-slate-950 rounded border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="text-xs font-semibold text-slate-200 mb-1">
                  Auto-Prioritize High Risk Alerts
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Instantly promotes alerts with risk &ge; 71 to the top of the analyst queue and broadcasts policy breach alerts.
                </p>
              </div>
              <label className="flex items-center gap-2 cursor-pointer pt-2">
                <input
                  type="checkbox"
                  checked={policy.auto_prioritize_high_risk}
                  onChange={(e) =>
                    setPolicy({ ...policy, auto_prioritize_high_risk: e.target.checked })
                  }
                  className="w-4 h-4 accent-cyan-400 rounded"
                />
                <span className="text-xs text-slate-300 font-medium">Active</span>
              </label>
            </div>

            {/* Toggle 3 */}
            <div className="p-4 bg-slate-950 rounded border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="text-xs font-semibold text-slate-200 mb-1">
                  Background Traffic Filtering
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Automatically discounts anomaly weights for verified internal DNS resolution flows under normal query frequencies.
                </p>
              </div>
              <label className="flex items-center gap-2 cursor-pointer pt-2">
                <input
                  type="checkbox"
                  checked={policy.enable_background_filtering}
                  onChange={(e) =>
                    setPolicy({ ...policy, enable_background_filtering: e.target.checked })
                  }
                  className="w-4 h-4 accent-cyan-400 rounded"
                />
                <span className="text-xs text-slate-300 font-medium">Active</span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
