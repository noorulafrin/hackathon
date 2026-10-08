import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header.tsx';
import { Sidebar, NavTab } from './components/Sidebar.tsx';
import { EvidenceModal } from './components/EvidenceModal.tsx';
import { DashboardView } from './components/views/DashboardView.tsx';
import { TelemetryInputView } from './components/views/TelemetryInputView.tsx';
import { ThreatDetectionView } from './components/views/ThreatDetectionView.tsx';
import { AlertsView } from './components/views/AlertsView.tsx';
import { AnalyticsView } from './components/views/AnalyticsView.tsx';
import { AuditLogsView } from './components/views/AuditLogsView.tsx';
import { SecurityPolicyView } from './components/views/SecurityPolicyView.tsx';
import { SystemHealthView } from './components/views/SystemHealthView.tsx';
import {
  fetchAlerts,
  fetchAnalytics,
  updateAlertStatus,
  runDemoSimulation,
} from './services/api.ts';
import { SecurityAlert, SOCAnalytics, AlertStatus } from './types/cyber.ts';
import { AlertCircle } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [analytics, setAnalytics] = useState<SOCAnalytics | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [isDemoRunning, setIsDemoRunning] = useState<boolean>(false);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [notification, setNotification] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [fetchedAlerts, fetchedAnalytics] = await Promise.all([
        fetchAlerts({ limit: 300 }),
        fetchAnalytics(),
      ]);
      setAlerts(fetchedAlerts);
      setAnalytics(fetchedAnalytics);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Error refreshing CyberSentinel data:', err);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleRunDemo = async () => {
    try {
      setIsDemoRunning(true);
      setNotification('Executing multi-vector cyber attack simulation...');
      const res = await runDemoSimulation();
      await loadData();
      setNotification(`Simulation finished: ${res.events_processed} events processed, ${res.alerts_generated} alerts generated.`);
      setTimeout(() => setNotification(null), 5000);
    } catch (err: any) {
      setNotification(`Demo simulation failed: ${err.message}`);
    } finally {
      setIsDemoRunning(false);
    }
  };

  const handleUpdateAlertStatus = async (alertId: string, status: AlertStatus) => {
    try {
      const updated = await updateAlertStatus(alertId, status);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: updated.status } : a))
      );
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, status: updated.status } : null));
      }
      loadData();
    } catch (err) {
      console.error('Error updating status:', err);
    }
  };

  const handleIngestSuccess = (newAlerts: SecurityAlert[]) => {
    loadData();
    setNotification(`Successfully ingested telemetry: ${newAlerts.length} new alerts detected.`);
    setTimeout(() => setNotification(null), 5000);
  };

  const policyBreaches = alerts.filter((a) => a.policy_breach).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <Header
        lastUpdated={lastUpdated}
        onRefresh={loadData}
        onRunDemo={handleRunDemo}
        isDemoRunning={isDemoRunning}
        policyBreachesCount={policyBreaches}
      />

      {/* Demo Notification Toast */}
      {notification && (
        <div className="bg-cyan-950 border-b border-cyan-500/40 px-6 py-2 text-xs text-cyan-200 flex items-center justify-between sticky top-16 z-20 transition-all">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{notification}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-cyan-400 hover:text-cyan-100 text-[11px] font-mono ml-4"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Main Layout Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Navigation Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onTabChange={setCurrentTab}
          alertCount={alerts.length}
          breachCount={policyBreaches}
        />

        {/* Viewport Content */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950">
          <div className="max-w-[1500px] mx-auto">
            {currentTab === 'dashboard' && (
              <DashboardView
                analytics={analytics}
                alerts={alerts}
                onSelectAlert={setSelectedAlert}
                onNavigateToTelemetry={() => setCurrentTab('telemetry')}
              />
            )}

            {currentTab === 'telemetry' && (
              <TelemetryInputView onIngestSuccess={handleIngestSuccess} />
            )}

            {currentTab === 'detection' && (
              <ThreatDetectionView alerts={alerts} onSelectAlert={setSelectedAlert} />
            )}

            {currentTab === 'alerts' && (
              <AlertsView
                alerts={alerts}
                onSelectAlert={setSelectedAlert}
                onUpdateStatus={handleUpdateAlertStatus}
              />
            )}

            {currentTab === 'analytics' && <AnalyticsView analytics={analytics} />}

            {currentTab === 'audit' && <AuditLogsView />}

            {currentTab === 'policy' && <SecurityPolicyView onPolicyUpdated={loadData} />}

            {currentTab === 'health' && <SystemHealthView onResetComplete={loadData} />}
          </div>
        </main>
      </div>

      {/* Explainable Alert Evidence Modal */}
      {selectedAlert && (
        <EvidenceModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdateStatus={handleUpdateAlertStatus}
        />
      )}
    </div>
  );
}
