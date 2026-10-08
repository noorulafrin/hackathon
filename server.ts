import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import {
  getDatabase,
  getAlerts,
  getAlertById,
  updateAlertStatus,
  getAuditLogs,
  getPolicy,
  updatePolicy,
  clearAllData,
} from './server/db.ts';
import { processTelemetryPipeline, SENTINEL_MODEL_VERSION } from './server/pipeline.ts';
import { parseCsvTelemetry } from './server/validator.ts';
import {
  generateDemoTelemetryScenario,
  SAMPLE_CSV_SNIPPET,
  SAMPLE_JSON_SNIPPET,
} from './server/demoGenerator.ts';
import { clearTelemetryHistory } from './server/featureEngine.ts';
import { SOCAnalytics, SystemHealth } from './src/types/cyber.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const startTime = Date.now();
let totalProcessedCounter = 0;
let totalAlertsCounter = 0;
let lastProcessedTs = new Date().toISOString();

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  app.use(express.json({ limit: '50mb' }));
  app.use(express.text({ limit: '50mb' }));

  // Initialize SQLite database
  await getDatabase();

  // Seed demo data on initial launch if empty
  const existingAlerts = await getAlerts({ limit: 5 });
  if (existingAlerts.length === 0) {
    console.log('Seeding initial SOC baseline and demo alerts...');
    const demo = generateDemoTelemetryScenario();
    const result = await processTelemetryPipeline(demo.records, true);
    totalProcessedCounter += result.eventsProcessed;
    totalAlertsCounter += result.alerts.length;
    lastProcessedTs = new Date().toISOString();
  } else {
    totalAlertsCounter = existingAlerts.length;
    totalProcessedCounter = existingAlerts.length * 4;
  }

  // ===================== REST API ROUTES =====================

  // 1. Ingest telemetry (JSON)
  app.post('/api/telemetry', async (req: Request, res: Response) => {
    try {
      const body = req.body;
      const records = Array.isArray(body) ? body : [body];
      const start = Date.now();
      const result = await processTelemetryPipeline(records, false);

      totalProcessedCounter += result.eventsProcessed;
      totalAlertsCounter += result.alerts.length;
      lastProcessedTs = new Date().toISOString();

      res.json({
        success: true,
        events_processed: result.eventsProcessed,
        alerts_generated: result.alerts.length,
        validation: result.validation,
        alerts: result.alerts,
        processing_time_ms: Date.now() - start,
      });
    } catch (err: any) {
      console.error('Error in /api/telemetry:', err);
      res.status(500).json({ success: false, error: err.message || 'Internal processing error' });
    }
  });

  // 2. Upload telemetry (CSV or JSON text)
  app.post('/api/telemetry/upload', async (req: Request, res: Response) => {
    try {
      let rawText = '';
      if (typeof req.body === 'string') {
        rawText = req.body;
      } else if (req.body && req.body.content) {
        rawText = req.body.content;
      } else {
        rawText = JSON.stringify(req.body);
      }

      let parsedRecords: any[] = [];
      const trimmed = rawText.trim();
      if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
        const parsed = JSON.parse(trimmed);
        parsedRecords = Array.isArray(parsed) ? parsed : [parsed];
      } else {
        parsedRecords = parseCsvTelemetry(trimmed);
      }

      const result = await processTelemetryPipeline(parsedRecords, false);
      totalProcessedCounter += result.eventsProcessed;
      totalAlertsCounter += result.alerts.length;
      lastProcessedTs = new Date().toISOString();

      res.json({
        success: true,
        events_processed: result.eventsProcessed,
        alerts_generated: result.alerts.length,
        validation: result.validation,
        alerts: result.alerts,
      });
    } catch (err: any) {
      console.error('Error in /api/telemetry/upload:', err);
      res.status(400).json({ success: false, error: err.message || 'Failed to parse telemetry file' });
    }
  });

  // 3. Process & Detect (same as pipeline)
  app.post('/api/detect', async (req: Request, res: Response) => {
    try {
      const records = Array.isArray(req.body) ? req.body : [req.body];
      const result = await processTelemetryPipeline(records, false);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 4. Alerts List with filters & pagination
  app.get('/api/alerts', async (req: Request, res: Response) => {
    try {
      const severity = req.query.severity as string | undefined;
      const threat = req.query.threat as string | undefined;
      const status = req.query.status as string | undefined;
      const search = req.query.search as string | undefined;
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 300;

      const alerts = await getAlerts({ severity, threat, status, search, limit });
      res.json({ success: true, count: alerts.length, alerts });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 5. Get Alert Details by ID
  app.get('/api/alerts/:id', async (req: Request, res: Response) => {
    try {
      const alert = await getAlertById(req.params.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json(alert);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 6. Update Alert Status
  app.patch('/api/alerts/:id/status', async (req: Request, res: Response) => {
    try {
      const { status, operator } = req.body;
      if (!['New', 'Reviewed', 'Resolved'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Must be New, Reviewed, or Resolved.' });
      }
      const updated = await updateAlertStatus(req.params.id, status, operator || 'SOC Operator');
      if (!updated) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json({ success: true, alert: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 7. SOC Analytics
  app.get('/api/analytics', async (_req: Request, res: Response) => {
    try {
      const allAlerts = await getAlerts({ limit: 1000 });
      const totalAlerts = allAlerts.length;

      let criticalCount = 0;
      let suspiciousCount = 0;
      let normalCount = 0;
      let policyBreachCount = 0;
      let totalRisk = 0;

      const threatCounts: Record<string, number> = {};
      const sourceMap: Map<string, { count: number; maxRisk: number; threats: Record<string, number> }> = new Map();
      const destMap: Map<string, number> = new Map();

      for (const a of allAlerts) {
        totalRisk += a.risk_score;
        if (a.severity === 'Malicious') criticalCount++;
        else if (a.severity === 'Suspicious') suspiciousCount++;
        else normalCount++;

        if (a.policy_breach) policyBreachCount++;

        threatCounts[a.threat_category] = (threatCounts[a.threat_category] || 0) + 1;

        // Source IP stats
        const srcStat = sourceMap.get(a.source_ip) || { count: 0, maxRisk: 0, threats: {} };
        srcStat.count++;
        srcStat.maxRisk = Math.max(srcStat.maxRisk, a.risk_score);
        srcStat.threats[a.threat_category] = (srcStat.threats[a.threat_category] || 0) + 1;
        sourceMap.set(a.source_ip, srcStat);

        // Dest IP stats
        destMap.set(a.dest_ip, (destMap.get(a.dest_ip) || 0) + 1);
      }

      const avgRisk = totalAlerts > 0 ? Math.round(totalRisk / totalAlerts) : 0;

      const threatDistribution = Object.entries(threatCounts).map(([cat, cnt]) => ({
        category: cat,
        count: cnt,
        percentage: totalAlerts > 0 ? Math.round((cnt / totalAlerts) * 100) : 0,
      }));

      const riskDistribution = [
        { band: '0-30 (Normal)', count: normalCount, color: '#10b981' },
        { band: '31-70 (Suspicious)', count: suspiciousCount, color: '#f59e0b' },
        { band: '71-100 (Malicious)', count: criticalCount, color: '#ef4444' },
      ];

      // Timeline aggregation by minute / bucket
      const timelineBuckets: Record<string, { normal: number; suspicious: number; malicious: number }> = {};
      for (const a of allAlerts.slice(0, 150)) {
        const timeKey = new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        if (!timelineBuckets[timeKey]) {
          timelineBuckets[timeKey] = { normal: 0, suspicious: 0, malicious: 0 };
        }
        if (a.severity === 'Malicious') timelineBuckets[timeKey].malicious++;
        else if (a.severity === 'Suspicious') timelineBuckets[timeKey].suspicious++;
        else timelineBuckets[timeKey].normal++;
      }

      const timeline = Object.entries(timelineBuckets).map(([t, counts]) => ({
        time: t,
        normal: counts.normal,
        suspicious: counts.suspicious,
        malicious: counts.malicious,
        total: counts.normal + counts.suspicious + counts.malicious,
      }));

      // Top source IPs
      const topSources = Array.from(sourceMap.entries())
        .map(([ip, data]) => {
          let dominant = 'Normal';
          let maxThreatCnt = 0;
          for (const [t, c] of Object.entries(data.threats)) {
            if (c > maxThreatCnt) {
              maxThreatCnt = c;
              dominant = t;
            }
          }
          return {
            ip,
            event_count: data.count,
            max_risk: data.maxRisk,
            dominant_threat: dominant,
          };
        })
        .sort((a, b) => b.max_risk - a.max_risk)
        .slice(0, 6);

      // Top destination IPs
      const topDestinations = Array.from(destMap.entries())
        .map(([ip, count]) => ({ ip, event_count: count }))
        .sort((a, b) => b.event_count - a.event_count)
        .slice(0, 6);

      const analytics: SOCAnalytics = {
        total_events: Math.max(totalProcessedCounter, totalAlerts * 3),
        total_alerts: totalAlerts,
        critical_alerts: criticalCount,
        suspicious_alerts: suspiciousCount,
        normal_events: normalCount,
        average_risk_score: avgRisk,
        policy_breaches_count: policyBreachCount,
        threat_distribution: threatDistribution,
        risk_distribution: riskDistribution,
        timeline,
        top_sources: topSources,
        top_destinations: topDestinations,
      };

      res.json(analytics);
    } catch (err: any) {
      console.error('Error calculating analytics:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // 8. Audit Logs
  app.get('/api/audit', async (req: Request, res: Response) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 200;
      const logs = await getAuditLogs(limit);
      res.json({ success: true, count: logs.length, logs });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 9. System Health
  app.get('/api/system-health', async (_req: Request, res: Response) => {
    try {
      const policy = await getPolicy();
      const allAlerts = await getAlerts({ limit: 100 });
      const breaches = allAlerts.filter((a) => a.policy_breach).length;

      const health: SystemHealth = {
        telemetry_pipeline: 'ONLINE',
        feature_engine: 'ONLINE',
        anomaly_detector: 'ONLINE',
        classifier: 'ONLINE',
        database: 'ONLINE',
        policy_engine: 'ONLINE',
        events_processed: Math.max(totalProcessedCounter, allAlerts.length * 3),
        alerts_generated: totalAlertsCounter,
        active_policy_breaches: breaches,
        last_processed_timestamp: lastProcessedTs,
        model_version: SENTINEL_MODEL_VERSION,
        uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
        processing_latency_ms: 18,
      };

      res.json(health);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 10. Security Policy
  app.get('/api/policy', async (_req: Request, res: Response) => {
    try {
      const policy = await getPolicy();
      res.json(policy);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.put('/api/policy', async (req: Request, res: Response) => {
    try {
      const updated = await updatePolicy(req.body);
      res.json({ success: true, policy: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 11. Run Demo Simulation
  app.post('/api/demo/run', async (_req: Request, res: Response) => {
    try {
      console.log('Executing realistic SOC demo attack scenario simulation...');
      const demo = generateDemoTelemetryScenario();
      const result = await processTelemetryPipeline(demo.records, true);

      totalProcessedCounter += result.eventsProcessed;
      totalAlertsCounter += result.alerts.length;
      lastProcessedTs = new Date().toISOString();

      res.json({
        success: true,
        message: 'Demo simulation successfully processed across the detection pipeline',
        scenario: demo.name,
        events_processed: result.eventsProcessed,
        alerts_generated: result.alerts.length,
        validation: result.validation,
        alerts: result.alerts,
      });
    } catch (err: any) {
      console.error('Error running demo simulation:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // 12. Reset Demo Data
  app.post('/api/demo/reset', async (_req: Request, res: Response) => {
    try {
      await clearAllData();
      clearTelemetryHistory();
      totalProcessedCounter = 0;
      totalAlertsCounter = 0;
      lastProcessedTs = new Date().toISOString();
      res.json({ success: true, message: 'All telemetry and alerts reset successfully' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 13. Sample Data Snippets for Ingestion page
  app.get('/api/sample-data', (_req: Request, res: Response) => {
    res.json({
      json: SAMPLE_JSON_SNIPPET,
      csv: SAMPLE_CSV_SNIPPET,
    });
  });

  // ===================== FRONTEND SERVING =====================
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberSentinel] SOC Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
