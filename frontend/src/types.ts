export type Metric = { total_runs: number; total_tests: number; attack_block_rate: number; sensitive_protection_rate: number; critical_findings: number; active_alerts: number; connected_providers: number; defenses_enabled: number }
export type Overview = { metrics: Metric; findings_by_severity: Array<{name:string;value:number}>; attack_outcomes: Array<{name:string;value:number}>; recent_runs: TestRun[]; recent_findings: Finding[]; metric_note: string }
export type TestRun = { id: string; status: string; defenses_enabled: boolean; created_at: string; completed_at?: string; metrics: Record<string, number>; results?: TestResult[]; findings?: Finding[] }
export type TestResult = { id:string; test_id:string; category:string; outcome:string; blocked:boolean; response_excerpt:string; evidence: Record<string, unknown> }
export type Finding = { id:string; run_id?:string; title:string; category:string; severity:string; confidence:string; explanation:string; evidence:string; recommendation:string; scanner:string; verification_status:string; created_at:string }
export type Policy = { id:string; key:string; name:string; description:string; severity:string; enabled:boolean; false_positive_note:string }
export type Provider = { id:string; name:string; provider:string; model:string; base_url?:string; secret_env_var?:string; has_server_secret_reference:boolean; active:boolean; status:string; created_at:string }
export type Patch = { id:string; finding_id?:string; title:string; diff:string; status:string; approved_by?:string; backup_reference?:string; created_at:string }
