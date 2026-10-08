import React, { useState, useEffect } from 'react';
import {
  UploadCloud,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Copy,
  Check,
  FileSpreadsheet,
} from 'lucide-react';
import { ingestTelemetry, uploadTelemetryFile, fetchSampleData } from '../../services/api.ts';
import { ValidationSummary, SecurityAlert } from '../../types/cyber.ts';

interface TelemetryInputViewProps {
  onIngestSuccess: (alerts: SecurityAlert[]) => void;
}

export const TelemetryInputView: React.FC<TelemetryInputViewProps> = ({ onIngestSuccess }) => {
  const [activeTab, setActiveTab] = useState<'paste' | 'upload' | 'samples'>('paste');
  const [telemetryText, setTelemetryText] = useState<string>('');
  const [sampleData, setSampleData] = useState<{ json: string; csv: string } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [resultSummary, setResultSummary] = useState<{
    events_processed: number;
    alerts_generated: number;
    validation: ValidationSummary;
  } | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    fetchSampleData()
      .then((data) => {
        setSampleData(data);
        setTelemetryText(data.json);
      })
      .catch((err) => console.error('Failed to load sample data:', err));
  }, []);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
      const content = event.target?.result as string;
      setTelemetryText(content);
      setActiveTab('paste');
    };
    reader.readAsText(file);
  };

  const handleProcessTelemetry = async () => {
    setErrorMsg(null);
    setLoading(true);
    setResultSummary(null);

    try {
      const res = await uploadTelemetryFile(telemetryText);
      setResultSummary({
        events_processed: res.events_processed,
        alerts_generated: res.alerts_generated,
        validation: res.validation,
      });
      if (res.alerts && res.alerts.length > 0) {
        onIngestSuccess(res.alerts);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Error processing telemetry ingestion');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSampleScenario = (type: 'portscan' | 'bruteforce' | 'exfil' | 'lateral' | 'mixed') => {
    const now = new Date();
    if (type === 'portscan') {
      const records = Array.from({ length: 30 }).map((_, i) => ({
        timestamp: new Date(now.getTime() - (30 - i) * 1000).toISOString(),
        source_ip: '192.168.1.45',
        dest_ip: '192.168.1.200',
        src_port: 52000 + i,
        dest_port: 20 + i * 2,
        protocol: 'TCP',
        bytes: 64,
        packets: 1,
        auth_status: 'none',
        event_type: 'connection',
      }));
      setTelemetryText(JSON.stringify(records, null, 2));
    } else if (type === 'bruteforce') {
      const records = Array.from({ length: 25 }).map((_, i) => ({
        timestamp: new Date(now.getTime() - (50 - i * 2) * 1000).toISOString(),
        source_ip: '10.0.0.88',
        dest_ip: '10.0.0.5',
        src_port: 49000 + i,
        dest_port: 22,
        protocol: 'SSH',
        bytes: 1400,
        packets: 6,
        auth_status: 'failure',
        event_type: 'auth',
      }));
      setTelemetryText(JSON.stringify(records, null, 2));
    } else if (type === 'exfil') {
      const records = [
        {
          timestamp: new Date().toISOString(),
          source_ip: '10.0.0.33',
          dest_ip: '203.0.113.88',
          src_port: 58110,
          dest_port: 443,
          protocol: 'HTTPS',
          bytes: 750 * 1024 * 1024,
          packets: 520000,
          auth_status: 'none',
          event_type: 'file_transfer',
        },
      ];
      setTelemetryText(JSON.stringify(records, null, 2));
    } else if (type === 'lateral') {
      const records = Array.from({ length: 12 }).map((_, i) => ({
        timestamp: new Date(now.getTime() - (24 - i * 2) * 1000).toISOString(),
        source_ip: '10.0.1.75',
        dest_ip: `10.0.2.${10 + i * 5}`,
        src_port: 50100 + i,
        dest_port: 445,
        protocol: 'SMB',
        bytes: 42000,
        packets: 50,
        auth_status: 'success',
        event_type: 'connection',
      }));
      setTelemetryText(JSON.stringify(records, null, 2));
    } else {
      if (sampleData) setTelemetryText(sampleData.json);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(telemetryText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Network Telemetry Ingestion Pipeline
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingest structured JSON or CSV security events with schema validation and fault tolerance.
          </p>
        </div>
      </div>

      {/* Schema Reference Card */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="text-xs font-semibold text-slate-200 mb-2">
          Required Telemetry Attributes Specification
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-[11px] font-mono">
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">timestamp</span>
            <span className="text-slate-500 block">ISO-8601 date</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">source_ip</span>
            <span className="text-slate-500 block">IPv4 or IPv6</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">dest_ip</span>
            <span className="text-slate-500 block">IPv4 or IPv6</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">src_port / dest_port</span>
            <span className="text-slate-500 block">0–65535 integer</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">protocol</span>
            <span className="text-slate-500 block">TCP, UDP, SMB, SSH...</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">bytes</span>
            <span className="text-slate-500 block">Total egress bytes</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">packets</span>
            <span className="text-slate-500 block">Packet frame count</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
            <span className="text-cyan-400 font-bold">auth_status</span>
            <span className="text-slate-500 block">success, failure, none</span>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800/80 col-span-2">
            <span className="text-cyan-400 font-bold">event_type</span>
            <span className="text-slate-500 block">connection, auth, flow, dns, file_transfer</span>
          </div>
        </div>
      </div>

      {/* Main Ingestion Panel */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {/* Ingestion Tabs */}
        <div className="p-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
          <div className="flex items-center gap-1">
            <button
              onClick={() => setActiveTab('paste')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'paste'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Paste JSON / CSV</span>
            </button>
            <button
              onClick={() => setActiveTab('upload')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'upload'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>Upload File</span>
            </button>
            <button
              onClick={() => setActiveTab('samples')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'samples'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              <span>Curated Attack Scenarios</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
              title="Copy payload"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={() => setTelemetryText('')}
              className="p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
              title="Clear editor"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Content */}
        <div className="p-4 space-y-4">
          {activeTab === 'upload' && (
            <div className="p-8 border-2 border-dashed border-slate-700/80 rounded-lg flex flex-col items-center justify-center bg-slate-950/40 text-center">
              <UploadCloud className="w-10 h-10 text-cyan-400 mb-3" />
              <h3 className="text-sm font-semibold text-slate-200 mb-1">
                Select or Drop Telemetry File
              </h3>
              <p className="text-xs text-slate-400 mb-4 max-w-sm">
                Supports structured <code className="text-cyan-300">.json</code> or{' '}
                <code className="text-cyan-300">.csv</code> files containing network flow logs.
              </p>
              <label className="px-4 py-2 text-xs font-semibold bg-cyan-400 text-slate-950 hover:bg-cyan-300 rounded-md cursor-pointer transition-colors shadow-sm">
                <span>Browse File</span>
                <input
                  type="file"
                  accept=".json,.csv,text/csv,application/json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          )}

          {activeTab === 'samples' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <button
                onClick={() => handleLoadSampleScenario('portscan')}
                className="p-3 text-left bg-slate-950 rounded border border-slate-800 hover:border-amber-500/50 transition-colors group"
              >
                <div className="text-xs font-bold text-amber-400 mb-1">Port Scan Attack</div>
                <div className="text-[11px] text-slate-400">
                  30 unique destination ports scanned within 30s.
                </div>
              </button>
              <button
                onClick={() => handleLoadSampleScenario('bruteforce')}
                className="p-3 text-left bg-slate-950 rounded border border-slate-800 hover:border-red-500/50 transition-colors group"
              >
                <div className="text-xs font-bold text-red-400 mb-1">Brute Force Auth</div>
                <div className="text-[11px] text-slate-400">
                  25 failed SSH authentications within 50s.
                </div>
              </button>
              <button
                onClick={() => handleLoadSampleScenario('lateral')}
                className="p-3 text-left bg-slate-950 rounded border border-slate-800 hover:border-orange-500/50 transition-colors group"
              >
                <div className="text-xs font-bold text-orange-400 mb-1">Lateral Movement</div>
                <div className="text-[11px] text-slate-400">
                  SMB fan-out across 12 internal IP endpoints.
                </div>
              </button>
              <button
                onClick={() => handleLoadSampleScenario('exfil')}
                className="p-3 text-left bg-slate-950 rounded border border-slate-800 hover:border-purple-500/50 transition-colors group"
              >
                <div className="text-xs font-bold text-purple-400 mb-1">Data Exfiltration</div>
                <div className="text-[11px] text-slate-400">
                  750 MB outbound transfer to external host.
                </div>
              </button>
            </div>
          )}

          {/* Monospace Telemetry Editor */}
          <div className="relative">
            <textarea
              value={telemetryText}
              onChange={(e) => setTelemetryText(e.target.value)}
              placeholder="Paste raw JSON array or CSV telemetry here..."
              rows={12}
              className="w-full p-3 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-cyan-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed resize-y"
            />
          </div>

          {errorMsg && (
            <div className="p-3 rounded bg-red-950/80 border border-red-500/50 text-red-200 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Actions Bar */}
          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-400">
              Input characters: <span className="font-mono">{telemetryText.length}</span>
            </span>
            <button
              onClick={handleProcessTelemetry}
              disabled={loading || !telemetryText.trim()}
              className="flex items-center gap-2 px-5 py-2 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 text-xs font-bold rounded shadow-md shadow-cyan-950/40 transition-colors"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{loading ? 'Processing Pipeline...' : 'Validate & Ingest Telemetry'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* VALIDATION & INGESTION RESULTS CARD (MANDATORY REQUIREMENT) */}
      {resultSummary && (
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wide">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Telemetry Validation & Pipeline Results
            </div>
            <span className="text-[11px] font-mono text-cyan-400">
              {resultSummary.alerts_generated} Alerts Triggered
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3 bg-slate-950 rounded border border-slate-800">
              <div className="text-slate-400 text-[11px]">Total Records Ingested</div>
              <div className="font-mono text-base font-bold text-slate-100 mt-0.5">
                {resultSummary.validation.total_records}
              </div>
            </div>
            <div className="p-3 bg-slate-950 rounded border border-emerald-500/30">
              <div className="text-emerald-400 text-[11px]">Valid Records Processed</div>
              <div className="font-mono text-base font-bold text-emerald-400 mt-0.5">
                {resultSummary.validation.valid_records}
              </div>
            </div>
            <div className="p-3 bg-slate-950 rounded border border-amber-500/30">
              <div className="text-amber-400 text-[11px]">Skipped / Malformed Records</div>
              <div className="font-mono text-base font-bold text-amber-400 mt-0.5">
                {resultSummary.validation.skipped_records}
              </div>
            </div>
            <div className="p-3 bg-slate-950 rounded border border-cyan-500/30">
              <div className="text-cyan-400 text-[11px]">Alerts Generated</div>
              <div className="font-mono text-base font-bold text-cyan-400 mt-0.5">
                {resultSummary.alerts_generated}
              </div>
            </div>
          </div>

          {/* Validation Errors Table if any were skipped */}
          {resultSummary.validation.errors && resultSummary.validation.errors.length > 0 && (
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <div className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Gracefully Skipped Malformed Records ({resultSummary.validation.errors.length}):</span>
              </div>
              <div className="max-h-48 overflow-y-auto rounded border border-slate-800 bg-slate-950">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 text-slate-400 font-mono text-[10px] uppercase">
                    <tr>
                      <th className="py-2 px-3">Record #</th>
                      <th className="py-2 px-3">Field</th>
                      <th className="py-2 px-3">Validation Issue</th>
                      <th className="py-2 px-3">Raw Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
                    {resultSummary.validation.errors.map((err, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="py-1.5 px-3 text-slate-400">{err.record_index}</td>
                        <td className="py-1.5 px-3 text-amber-300">{err.field}</td>
                        <td className="py-1.5 px-3 text-slate-300 font-sans">{err.issue}</td>
                        <td className="py-1.5 px-3 text-slate-500 truncate max-w-xs">
                          {String(err.raw_value ?? '')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
