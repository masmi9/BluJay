"""Initial schema — all baseline tables.

Revision ID: 0001
Revises:
Create Date: 2026-04-17

Captures the full schema as it existed before Alembic was introduced.
Running `alembic upgrade head` on a brand-new database will replay every
migration in order and produce an identical result to the old
Base.metadata.create_all() call.

Existing databases that were already created via create_all() should be
stamped rather than re-migrated:
    alembic stamp head
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # analyses                                                             #
    # ------------------------------------------------------------------ #
    op.create_table(
        "analyses",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("apk_filename", sa.String, nullable=False),
        sa.Column("apk_sha256", sa.String, nullable=False),
        sa.Column("upload_path", sa.String, nullable=True),
        sa.Column("package_name", sa.String, nullable=True),
        sa.Column("version_name", sa.String, nullable=True),
        sa.Column("version_code", sa.Integer, nullable=True),
        sa.Column("min_sdk", sa.Integer, nullable=True),
        sa.Column("target_sdk", sa.Integer, nullable=True),
        # iOS / cross-platform columns (were added via _migrate_table previously)
        sa.Column("platform", sa.String, nullable=False, server_default="android"),
        sa.Column("bundle_id", sa.String, nullable=True),
        sa.Column("min_ios_version", sa.String, nullable=True),
        sa.Column("ats_config_json", sa.Text, nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("decompile_path", sa.String, nullable=True),
        sa.Column("jadx_path", sa.String, nullable=True),
    )
    op.create_index("ix_analyses_apk_sha256", "analyses", ["apk_sha256"], unique=True)

    # ------------------------------------------------------------------ #
    # static_findings                                                      #
    # ------------------------------------------------------------------ #
    op.create_table(
        "static_findings",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("category", sa.String, nullable=False),
        sa.Column("severity", sa.String, nullable=False),
        sa.Column("title", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("file_path", sa.String, nullable=True),
        sa.Column("line_number", sa.Integer, nullable=True),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("rule_id", sa.String, nullable=True),
    )
    op.create_index("ix_static_findings_analysis_id", "static_findings", ["analysis_id"])

    # ------------------------------------------------------------------ #
    # dynamic_sessions                                                     #
    # ------------------------------------------------------------------ #
    op.create_table(
        "dynamic_sessions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("device_serial", sa.String, nullable=False),
        sa.Column("package_name", sa.String, nullable=False),
        sa.Column("platform", sa.String, nullable=False, server_default="android"),
        sa.Column("status", sa.String, nullable=False, server_default="active"),
        sa.Column("proxy_port", sa.Integer, nullable=True),
        sa.Column("frida_attached", sa.Boolean, nullable=False, server_default="0"),
    )
    op.create_index("ix_dynamic_sessions_analysis_id", "dynamic_sessions", ["analysis_id"])

    # ------------------------------------------------------------------ #
    # proxy_flows                                                          #
    # ------------------------------------------------------------------ #
    op.create_table(
        "proxy_flows",
        sa.Column("id", sa.String, primary_key=True),   # mitmproxy flow UUID
        sa.Column("session_id", sa.Integer,
                  sa.ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("method", sa.String, nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("host", sa.String, nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("request_headers", sa.Text, nullable=False),
        sa.Column("request_body", sa.LargeBinary, nullable=True),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_headers", sa.Text, nullable=True),
        sa.Column("response_body", sa.LargeBinary, nullable=True),
        sa.Column("tls", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("content_type", sa.String, nullable=True),
        sa.Column("duration_ms", sa.Float, nullable=True),
    )
    op.create_index("ix_proxy_flows_session_id", "proxy_flows", ["session_id"])

    # ------------------------------------------------------------------ #
    # frida_events                                                         #
    # ------------------------------------------------------------------ #
    op.create_table(
        "frida_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("session_id", sa.Integer,
                  sa.ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("event_type", sa.String, nullable=False),
        sa.Column("script_name", sa.String, nullable=True),
        sa.Column("payload", sa.Text, nullable=False),
    )
    op.create_index("ix_frida_events_session_id", "frida_events", ["session_id"])

    # ------------------------------------------------------------------ #
    # owasp_scans                                                          #
    # ------------------------------------------------------------------ #
    op.create_table(
        "owasp_scans",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("platform", sa.String, nullable=False, server_default="android"),
        sa.Column("apk_path", sa.String, nullable=False),
        sa.Column("package_name", sa.String, nullable=True),
        sa.Column("mode", sa.String, nullable=False, server_default="deep"),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("progress", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_json", sa.Text, nullable=True),
        sa.Column("summary_json", sa.Text, nullable=True),
        sa.Column("report_html", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("duration_s", sa.Float, nullable=True),
    )
    op.create_index("ix_owasp_scans_analysis_id", "owasp_scans", ["analysis_id"])

    # ------------------------------------------------------------------ #
    # agent_commands                                                       #
    # ------------------------------------------------------------------ #
    op.create_table(
        "agent_commands",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("device_serial", sa.String, nullable=False),
        sa.Column("command_type", sa.String, nullable=False),
        sa.Column("args", sa.Text, nullable=True),
        sa.Column("result", sa.Text, nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Float, nullable=True),
    )

    # ------------------------------------------------------------------ #
    # ollama_analyses                                                      #
    # ------------------------------------------------------------------ #
    op.create_table(
        "ollama_analyses",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("session_id", sa.Integer, nullable=True),
        sa.Column("source", sa.String, nullable=False),
        sa.Column("scan_input", sa.Text, nullable=False),
        sa.Column("ai_response", sa.Text, nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Float, nullable=True),
        sa.Column("model_used", sa.String, nullable=False, server_default="metatron-qwen"),
    )

    # ------------------------------------------------------------------ #
    # strix_scans                                                          #
    # ------------------------------------------------------------------ #
    op.create_table(
        "strix_scans",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("session_id", sa.Integer, nullable=True),
        sa.Column("target", sa.String, nullable=False),
        sa.Column("scan_mode", sa.String, nullable=False, server_default="standard"),
        sa.Column("instruction", sa.Text, nullable=True),
        sa.Column("llm_model", sa.String, nullable=False, server_default="ollama/metatron-qwen"),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("pid", sa.Integer, nullable=True),
        sa.Column("run_name", sa.String, nullable=True),
        sa.Column("raw_output", sa.Text, nullable=True),
        sa.Column("findings_json", sa.Text, nullable=True),
        sa.Column("vuln_count", sa.Integer, nullable=True, server_default="0"),
        sa.Column("risk_level", sa.String, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
    )

    # ------------------------------------------------------------------ #
    # test_apps                                                            #
    # ------------------------------------------------------------------ #
    op.create_table(
        "test_apps",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("display_name", sa.String, nullable=False),
        sa.Column("package_name", sa.String, nullable=False),
        sa.Column("apk_path", sa.String, nullable=True),
        sa.Column("category", sa.String, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_vulnerable_app", sa.Boolean, nullable=False, server_default="0"),
    )
    op.create_index("ix_test_apps_package_name", "test_apps", ["package_name"])

    # ------------------------------------------------------------------ #
    # test_runs                                                            #
    # ------------------------------------------------------------------ #
    op.create_table(
        "test_runs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("test_app_id", sa.Integer,
                  sa.ForeignKey("test_apps.id", ondelete="CASCADE"), nullable=False),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("owasp_scan_id", sa.Integer,
                  sa.ForeignKey("owasp_scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("frida_script_name", sa.String, nullable=True),
        sa.Column("frida_script_source", sa.Text, nullable=True),
        sa.Column("findings_json", sa.Text, nullable=True),
        sa.Column("reproduction_steps", sa.Text, nullable=True),
        sa.Column("true_positives", sa.Integer, nullable=False, server_default="0"),
        sa.Column("false_positives", sa.Integer, nullable=False, server_default="0"),
        sa.Column("false_negatives", sa.Integer, nullable=False, server_default="0"),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_test_runs_test_app_id", "test_runs", ["test_app_id"])

    # ------------------------------------------------------------------ #
    # api_test_suites                                                      #
    # ------------------------------------------------------------------ #
    op.create_table(
        "api_test_suites",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("session_id", sa.Integer,
                  sa.ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("target_app", sa.String, nullable=True),
        sa.Column("platform", sa.String, nullable=True, server_default="android"),
        sa.Column("status", sa.String, nullable=True, server_default="building"),
        sa.Column("flow_count", sa.Integer, nullable=True, server_default="0"),
        sa.Column("auth_contexts_json", sa.Text, nullable=True),
        sa.Column("collected_ids_json", sa.Text, nullable=True),
    )
    op.create_index("ix_api_test_suites_session_id", "api_test_suites", ["session_id"])
    op.create_index("ix_api_test_suites_analysis_id", "api_test_suites", ["analysis_id"])

    # ------------------------------------------------------------------ #
    # api_tests                                                            #
    # ------------------------------------------------------------------ #
    op.create_table(
        "api_tests",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("suite_id", sa.Integer,
                  sa.ForeignKey("api_test_suites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("test_type", sa.String, nullable=False),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("method", sa.String, nullable=True, server_default="GET"),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("headers_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("body", sa.Text, nullable=True),
        sa.Column("config_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("status", sa.String, nullable=True, server_default="pending"),
        sa.Column("run_count", sa.Integer, nullable=True, server_default="0"),
        sa.Column("vulnerable_count", sa.Integer, nullable=True, server_default="0"),
    )
    op.create_index("ix_api_tests_suite_id", "api_tests", ["suite_id"])

    # ------------------------------------------------------------------ #
    # api_test_results                                                     #
    # ------------------------------------------------------------------ #
    op.create_table(
        "api_test_results",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("test_id", sa.Integer,
                  sa.ForeignKey("api_tests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("label", sa.String, nullable=True),
        sa.Column("request_method", sa.String, nullable=True),
        sa.Column("request_url", sa.Text, nullable=True),
        sa.Column("request_headers_json", sa.Text, nullable=True),
        sa.Column("request_body", sa.Text, nullable=True),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_headers_json", sa.Text, nullable=True),
        sa.Column("response_body", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("is_vulnerable", sa.Boolean, nullable=True, server_default="0"),
        sa.Column("finding", sa.Text, nullable=True),
        sa.Column("severity", sa.String, nullable=True),
        sa.Column("diff_summary", sa.Text, nullable=True),
    )
    op.create_index("ix_api_test_results_test_id", "api_test_results", ["test_id"])


def downgrade() -> None:
    op.drop_table("api_test_results")
    op.drop_table("api_tests")
    op.drop_table("api_test_suites")
    op.drop_table("test_runs")
    op.drop_table("test_apps")
    op.drop_table("strix_scans")
    op.drop_table("ollama_analyses")
    op.drop_table("agent_commands")
    op.drop_table("owasp_scans")
    op.drop_table("frida_events")
    op.drop_table("proxy_flows")
    op.drop_table("dynamic_sessions")
    op.drop_table("static_findings")
    op.drop_table("analyses")
