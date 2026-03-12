-- Sprint 6: Audit runs and results for batch remediation history
-- Run in Supabase SQL Editor: jdvtlonneybqivcjtsj.supabase.co

-- One row per batch run
CREATE TABLE IF NOT EXISTS audit_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_at TIMESTAMPTZ DEFAULT now(),
    source_filename TEXT,
    total_resources INT,
    compliant_count INT,
    violation_count INT,
    avg_mttr_seconds FLOAT,
    policy_text TEXT,
    app_version TEXT DEFAULT '1.0.0'
);

-- One row per resource per run
CREATE TABLE IF NOT EXISTS audit_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID REFERENCES audit_runs(id) ON DELETE CASCADE,
    resource_id TEXT,
    resource_type TEXT,
    verdict TEXT,
    violations INT,
    mttr_seconds FLOAT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes for fast history queries
CREATE INDEX IF NOT EXISTS idx_audit_results_run_id ON audit_results(run_id);
CREATE INDEX IF NOT EXISTS idx_audit_runs_run_at ON audit_runs(run_at DESC);
