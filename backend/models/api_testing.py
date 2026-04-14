"""
API Testing module models.
Suites group test cases against a target app; tests run and produce results.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class ApiTestSuite(Base):
    __tablename__ = "api_test_suites"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    session_id = Column(Integer, ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String, nullable=False)
    target_app = Column(String, nullable=True)   # package_name or bundle_id
    platform = Column(String, default="android") # android | ios
    status = Column(String, default="building")  # building | ready | running | complete
    flow_count = Column(Integer, default=0)
    # JSON blobs updated by context builder
    auth_contexts_json = Column(Text, nullable=True)  # [{id, label, header_name, header_value, first_seen_url}]
    collected_ids_json = Column(Text, nullable=True)  # {endpoint_pattern: {param_name: [id1, id2, ...]}}

    tests = relationship("ApiTest", back_populates="suite", cascade="all, delete-orphan")


class ApiTest(Base):
    __tablename__ = "api_tests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    suite_id = Column(Integer, ForeignKey("api_test_suites.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    # idor_sweep | auth_strip | token_replay | cross_user_auth
    test_type = Column(String, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    # Request template
    method = Column(String, default="GET")
    url = Column(Text, nullable=False)
    headers_json = Column(Text, nullable=False, default="{}")
    body = Column(Text, nullable=True)
    # Test-specific config JSON
    config_json = Column(Text, nullable=False, default="{}")
    # pending | running | complete | failed
    status = Column(String, default="pending")
    run_count = Column(Integer, default=0)
    vulnerable_count = Column(Integer, default=0)

    suite = relationship("ApiTestSuite", back_populates="tests")
    results = relationship("ApiTestResult", back_populates="test", cascade="all, delete-orphan")


class ApiTestResult(Base):
    __tablename__ = "api_test_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    test_id = Column(Integer, ForeignKey("api_tests.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    # Human label: "baseline_with_auth", "no_auth_headers", "id_7557949468423800246", etc.
    label = Column(String, nullable=True)
    # Request
    request_method = Column(String, nullable=True)
    request_url = Column(Text, nullable=True)
    request_headers_json = Column(Text, nullable=True)
    request_body = Column(Text, nullable=True)
    # Response
    response_status = Column(Integer, nullable=True)
    response_headers_json = Column(Text, nullable=True)
    response_body = Column(Text, nullable=True)  # capped at 50 KB
    duration_ms = Column(Integer, nullable=True)
    # Analysis
    is_vulnerable = Column(Boolean, default=False)
    finding = Column(Text, nullable=True)
    severity = Column(String, nullable=True)   # critical | high | medium | low
    diff_summary = Column(Text, nullable=True)

    test = relationship("ApiTest", back_populates="results")
