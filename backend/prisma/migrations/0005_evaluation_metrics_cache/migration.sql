-- Private revisioned cache for aggregated evaluation metrics.
-- It stores aggregate results only; ground-truth rows remain isolated.
CREATE TABLE "evaluation"."evaluation_metric_cache" (
    "singleton" BOOLEAN NOT NULL DEFAULT TRUE,
    "revision" BIGINT NOT NULL DEFAULT 0,
    "payload" JSONB,
    CONSTRAINT "evaluation_metric_cache_pkey" PRIMARY KEY ("singleton"),
    CONSTRAINT "evaluation_metric_cache_singleton_check" CHECK ("singleton" = TRUE)
);

INSERT INTO "evaluation"."evaluation_metric_cache" ("singleton", "revision", "payload")
VALUES (TRUE, 0, NULL);

ALTER TABLE "evaluation"."evaluation_metric_cache" ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE "evaluation"."evaluation_metric_cache" FROM PUBLIC;
REVOKE ALL ON TABLE "evaluation"."evaluation_metric_cache" FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE "evaluation"."evaluation_metric_cache" TO service_role, risklens_app;
GRANT USAGE ON SCHEMA "evaluation" TO service_role, risklens_app;
CREATE POLICY "evaluation_metric_cache_backend_access"
ON "evaluation"."evaluation_metric_cache"
FOR ALL TO risklens_app
USING (TRUE) WITH CHECK (TRUE);

CREATE OR REPLACE FUNCTION "evaluation"."invalidate_evaluation_metric_cache"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, evaluation
AS $$
BEGIN
    UPDATE "evaluation"."evaluation_metric_cache"
       SET "revision" = "revision" + 1,
           "payload" = NULL
     WHERE "singleton" = TRUE;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION "evaluation"."invalidate_evaluation_metric_cache"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "evaluation"."invalidate_evaluation_metric_cache"() FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION "evaluation"."invalidate_evaluation_metric_cache"() TO risklens_app, service_role;

CREATE TRIGGER "evaluation_metrics_alerts_changed"
AFTER INSERT OR DELETE OR UPDATE OF "transactionId", "riskRuleId", "id"
ON "public"."alerts"
FOR EACH STATEMENT EXECUTE FUNCTION "evaluation"."invalidate_evaluation_metric_cache"();

CREATE TRIGGER "evaluation_metrics_rules_changed"
AFTER INSERT OR DELETE OR UPDATE OF "ruleCode", "id"
ON "public"."risk_rules"
FOR EACH STATEMENT EXECUTE FUNCTION "evaluation"."invalidate_evaluation_metric_cache"();

CREATE TRIGGER "evaluation_metrics_evidence_changed"
AFTER INSERT OR DELETE OR UPDATE OF "alertId", "id"
ON "public"."alert_evidence"
FOR EACH STATEMENT EXECUTE FUNCTION "evaluation"."invalidate_evaluation_metric_cache"();

CREATE TRIGGER "evaluation_metrics_validation_changed"
AFTER INSERT OR DELETE OR UPDATE OF "status"
ON "public"."validation_results"
FOR EACH STATEMENT EXECUTE FUNCTION "evaluation"."invalidate_evaluation_metric_cache"();

CREATE TRIGGER "evaluation_metrics_generation_changed"
AFTER INSERT OR DELETE OR UPDATE OF "startedAt", "completedAt"
ON "public"."generation_runs"
FOR EACH STATEMENT EXECUTE FUNCTION "evaluation"."invalidate_evaluation_metric_cache"();

CREATE TRIGGER "evaluation_metrics_labels_changed"
AFTER INSERT OR DELETE OR UPDATE OF "transactionId", "scenarioCode", "isSuspicious", "expectedRuleCode"
ON "evaluation"."ground_truth_labels"
FOR EACH STATEMENT EXECUTE FUNCTION "evaluation"."invalidate_evaluation_metric_cache"();
