import { TelemetryRecord, SecurityAlert, ValidationSummary } from '../src/types/cyber.ts';
import { validateTelemetryBatch, parseCsvTelemetry } from './validator.ts';
import { addRecordToHistory, extractBehavioralFeatures } from './featureEngine.ts';
import { detectAnomaly } from './anomalyDetector.ts';
import { classifyThreat } from './classifier.ts';
import { calculateDeterministicRiskScore } from './riskScorer.ts';
import { generateEvidenceExplanation } from './explainer.ts';
import { insertTelemetryRecord, insertAlert, getPolicy } from './db.ts';

export const SENTINEL_MODEL_VERSION = 'v2.4.1 SentinelCore-IForest';

export interface PipelineExecutionResult {
  validation: ValidationSummary;
  alerts: SecurityAlert[];
  eventsProcessed: number;
}

export async function processTelemetryPipeline(
  rawRecords: any[],
  isDemo: boolean = false
): Promise<PipelineExecutionResult> {
  const validation = validateTelemetryBatch(rawRecords);
  const { valid_records } = validation;
  const policy = await getPolicy();
  const generatedAlerts: SecurityAlert[] = [];

  for (const record of valid_records) {
    // 1. Persist raw telemetry
    await insertTelemetryRecord(record, isDemo);

    // 2. Add to sliding behavioral window buffer
    addRecordToHistory(record);

    // 3. Extract behavioral features with configured sliding window
    const features = extractBehavioralFeatures(record, policy.sliding_window_seconds);

    // 4. Anomaly detection via Isolation Forest
    const anomaly = detectAnomaly(features);

    // 5. Threat classification
    const classification = classifyThreat(features, anomaly.anomaly_score);

    // 6. Deterministic risk scoring
    const risk = calculateDeterministicRiskScore(features, anomaly.anomaly_score, classification);

    // 7. Evidence explanation and policy guardrail check
    const explanation = generateEvidenceExplanation(
      features,
      classification,
      anomaly,
      risk.risk_score,
      policy
    );

    // 8. Generate Security Alert
    // We generate an alert if it is suspicious, malicious, or a policy breach,
    // or if it represents an ingested event when requested for live surveillance.
    const isAlertWorthy =
      risk.risk_score >= 25 ||
      explanation.policy_breach ||
      classification.predicted_threat !== 'Normal' ||
      anomaly.is_anomalous;

    const alertId = `ALT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

    const alert: SecurityAlert = {
      id: alertId,
      timestamp: record.timestamp,
      source_ip: record.source_ip,
      dest_ip: record.dest_ip,
      src_port: record.src_port,
      dest_port: record.dest_port,
      protocol: record.protocol,
      threat_category: classification.predicted_threat,
      risk_score: risk.risk_score,
      severity: risk.severity,
      anomaly_score: anomaly.anomaly_score,
      confidence_pct: classification.confidence_pct,
      evidence_features: explanation.evidence_statements,
      recommended_action: explanation.recommended_action,
      status: 'New',
      policy_breach: explanation.policy_breach,
      model_version: SENTINEL_MODEL_VERSION,
      probabilities: classification.probabilities,
      behavioral_features: features,
      raw_telemetry: record,
      is_demo: isDemo,
    };

    if (isAlertWorthy) {
      await insertAlert(alert);
      generatedAlerts.push(alert);
    }
  }

  return {
    validation: validation.summary,
    alerts: generatedAlerts,
    eventsProcessed: valid_records.length,
  };
}
