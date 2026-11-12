-- Evaluation labels are private backend evaluation data.
-- Access is intentionally limited to trusted privileged backend connections.
ALTER TABLE "evaluation"."ground_truth_labels" ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON SCHEMA "evaluation" FROM PUBLIC;
REVOKE ALL ON TABLE "evaluation"."ground_truth_labels" FROM PUBLIC;
REVOKE ALL ON TABLE "evaluation"."ground_truth_labels" FROM anon, authenticated;

-- No anon/authenticated policy is created. The backend must use a trusted
-- service connection that is explicitly granted access by deployment policy.
