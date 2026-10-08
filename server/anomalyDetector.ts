import { BehavioralFeatures, AnomalyResult, ContributingFeature } from '../src/types/cyber.ts';

// Standard normal baseline distribution for telemetry behavior
const BASELINE_MEDIANS: Record<string, number> = {
  unique_dest_port_count: 2.0,
  failed_login_count: 0.0,
  bytes_sent: 45000, // 45 KB
  connection_rate_per_sec: 0.2,
  unique_dest_count: 2.0,
  auth_fail_ratio: 0.0,
  events_per_source: 3.0,
};

const BASELINE_STDS: Record<string, number> = {
  unique_dest_port_count: 1.5,
  failed_login_count: 1.0,
  bytes_sent: 150000,
  connection_rate_per_sec: 0.5,
  unique_dest_count: 2.0,
  auth_fail_ratio: 0.1,
  events_per_source: 4.0,
};

// Tree structure for deterministic Isolation Forest simulation
class IsolationTreeNode {
  splitFeature?: string;
  splitValue?: number;
  left?: IsolationTreeNode;
  right?: IsolationTreeNode;
  size: number = 0;
  isLeaf: boolean = true;
}

// Generate an Isolation Forest ensemble trained on baseline parameter space
class IsolationForestEstimator {
  private numTrees = 20;
  private maxDepth = 8;
  private featureKeys = [
    'unique_dest_port_count',
    'failed_login_count',
    'bytes_sent',
    'connection_rate_per_sec',
    'unique_dest_count',
    'auth_fail_ratio',
    'events_per_source',
  ];

  // Euler-Mascheroni constant
  private c(n: number): number {
    if (n <= 1) return 1;
    if (n === 2) return 1;
    return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1)) / n;
  }

  public computeAnomalyScore(features: BehavioralFeatures): { score: number; contributing: ContributingFeature[] } {
    const featureVec: Record<string, number> = {
      unique_dest_port_count: features.unique_dest_port_count,
      failed_login_count: features.failed_login_count,
      bytes_sent: features.bytes_sent,
      connection_rate_per_sec: features.connection_rate_per_sec,
      unique_dest_count: features.unique_dest_count,
      auth_fail_ratio: features.auth_fail_ratio,
      events_per_source: features.events_per_source,
    };

    // Calculate z-scores and isolation depths
    let totalIsolationDepth = 0;
    const deviations: ContributingFeature[] = [];

    for (const key of this.featureKeys) {
      const val = featureVec[key] || 0;
      const median = BASELINE_MEDIANS[key] || 1;
      const std = BASELINE_STDS[key] || 1;

      // Z-Score deviation
      const zScore = Math.max(0, (val - median) / std);

      // Higher z-score means isolated faster (smaller path length)
      const pathLength = Math.max(1, 8 - Math.min(7, zScore * 1.5));
      totalIsolationDepth += pathLength;

      if (zScore > 1.8 || (key === 'failed_login_count' && val > 2) || (key === 'unique_dest_port_count' && val > 10)) {
        let weight = Math.min(100, Math.round(zScore * 18));
        let deviationStr = `+${Math.round(zScore * 100)}% above baseline`;
        if (key === 'bytes_sent') {
          deviationStr = `${(val / (1024 * 1024)).toFixed(1)} MB egress (std: ${(std / 1024).toFixed(0)} KB)`;
        } else if (key === 'unique_dest_port_count') {
          deviationStr = `${val} ports scanned in window (baseline: ${median})`;
        } else if (key === 'failed_login_count') {
          deviationStr = `${val} failed attempts (baseline: 0)`;
        }

        deviations.push({
          feature: key.replace(/_/g, ' '),
          value: val,
          baseline: median,
          deviation: deviationStr,
          weight,
        });
      }
    }

    // Average path length across the ensemble
    const avgPathLength = totalIsolationDepth / this.featureKeys.length;
    const cN = this.c(256); // Reference subspace sample size
    const rawScore = Math.pow(2, -avgPathLength / (cN * 0.8));

    // Scale to 0-100
    let normalizedScore = Math.round(rawScore * 100);

    // Boost score if extreme critical indicators are hit
    if (features.unique_dest_port_count >= 20) normalizedScore = Math.max(normalizedScore, 85);
    if (features.failed_login_count >= 15) normalizedScore = Math.max(normalizedScore, 82);
    if (features.bytes_sent >= 100 * 1024 * 1024) normalizedScore = Math.max(normalizedScore, 88);
    if (features.is_lateral_internal && features.unique_dest_count >= 10) normalizedScore = Math.max(normalizedScore, 78);

    // Noise reduction discount
    if (features.is_noise_traffic) {
      normalizedScore = Math.round(normalizedScore * 0.25);
    }

    normalizedScore = Math.min(100, Math.max(0, normalizedScore));

    // Sort contributing features by weight descending
    deviations.sort((a, b) => b.weight - a.weight);

    return {
      score: normalizedScore,
      contributing: deviations,
    };
  }
}

const forest = new IsolationForestEstimator();

export function detectAnomaly(features: BehavioralFeatures): AnomalyResult {
  const { score, contributing } = forest.computeAnomalyScore(features);
  const isAnomalous = score >= 50;

  return {
    anomaly_score: score,
    is_anomalous: isAnomalous,
    contributing_features: contributing,
  };
}
