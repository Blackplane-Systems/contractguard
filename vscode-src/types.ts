export type Severity = 'info' | 'warning' | 'critical' | 'block';

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  description: string;
  explanation: string;
  suggestion: string;
  location: string;
  context: string;
  attack_vector: string;
  cwe: string;
  confidence: string;
}

export interface ScoreSummary {
  grade: string;
  score: number;
  total_findings: number;
  block_count: number;
  critical_count: number;
  warning_count: number;
  info_count: number;
  risk_summary: string;
  attack_surface: string[];
  top_risks: string[];
}

export interface ScanPayload {
  target: string;
  analyzer: string;
  engine_version: string;
  generated_at: string | null;
  findings: Finding[];
  score: ScoreSummary;
  sarif: Record<string, unknown> | null;
}
