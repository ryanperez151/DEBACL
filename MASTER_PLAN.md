# MASTER_PLAN: DEBACL

## Identity

**Type:** CLI / API security tool (PoC)
**Languages:** Python (100%)
**Root:** `C:/Users/Mango/debacl`
**Created:** 2026-03-04
**Last updated:** 2026-03-04

DEBACL (Dynamic Endpoint-Based Access Control List) is a security proof-of-concept that ingests network telemetry from EDR/MDM agents and authentication/connection telemetry from VPN gateways and IdPs, correlates "expected" managed-device IPs against "observed" connection source IPs, and surfaces anomalies -- managed devices authenticating from unexpected IPs, or unmanaged IPs reaching security edges.

## Architecture

```
src/debacl/
  models/          -- Pydantic data models (EndpointTelemetry, ConnectionEvent, Finding)
  collectors/      -- Adapter implementations per telemetry source (CrowdStrike, Intune, Jamf, Okta, Entra, VPN logs)
  normalization/   -- Transform raw API responses into canonical models
  correlation/     -- IP comparison engine: expected vs observed, anomaly detection
  output/          -- Reporting: JSON/CSV findings, severity scoring, optional SIEM export
  storage/         -- SQLite persistence via SQLAlchemy
  api/             -- FastAPI surface for triggering collections and querying findings
  config/          -- Settings, credentials management, source configuration
  cli/             -- CLI entry point (click or typer)
tests/             -- pytest test suite mirroring src/ structure
```

## Original Intent

> Create a MASTER_PLAN.md for the DEBACL project -- a Python-based security PoC that ingests network telemetry from EDR/MDM agents (current public IP of managed endpoints), ingests authentication/connection telemetry from VPN gateways and IdPs, compares "expected" IPs (from managed endpoint telemetry) vs "observed" IPs (from security edge logs), and surfaces anomalies: managed devices authenticating from unexpected IPs, or unmanaged IPs reaching security edges.

## Principles

1. **Adapter Isolation** -- Each telemetry source is a self-contained adapter behind a common interface. Adding a new source never modifies existing adapters or core logic.
2. **Canonical Models as Contract** -- All data flows through Pydantic models (`EndpointTelemetry`, `ConnectionEvent`, `Finding`). These models are the system's lingua franca; everything upstream normalizes to them, everything downstream consumes them.
3. **Offline-First PoC** -- The system must run entirely locally with SQLite and mock data. No cloud infrastructure required. Real API integrations are opt-in overlays.
4. **Fail Loud, Log Everything** -- Every collection attempt, correlation run, and anomaly detection is logged with timestamps and source metadata. Silent failures are unacceptable in a security tool.
5. **Severity is Configurable** -- Anomaly scoring thresholds and severity mappings are configuration, not code. Different organizations have different risk tolerances.

---

## Decision Log

| Date | DEC-ID | Initiative | Decision | Rationale |
|------|--------|-----------|----------|-----------|
| 2026-03-04 | DEC-MODEL-001 | debacl-poc | Pydantic v2 for all data models | Type safety, validation, serialization built-in; FastAPI native support |
| 2026-03-04 | DEC-DATA-001 | debacl-poc | Polars over pandas for data processing | Faster, lower memory, better type system, lazy evaluation for large datasets |
| 2026-03-04 | DEC-STORE-001 | debacl-poc | SQLite via SQLAlchemy for persistence | Zero infrastructure, portable, SQLAlchemy provides migration path to Postgres later |
| 2026-03-04 | DEC-COLLECT-001 | debacl-poc | Abstract base collector with Strategy pattern | Each source is a pluggable adapter; adding sources requires zero changes to core |
| 2026-03-04 | DEC-CORR-001 | debacl-poc | Set-based IP correlation with configurable time windows | Simple, auditable, performant for PoC scale; time windows prevent stale-IP false positives |
| 2026-03-04 | DEC-PKG-001 | debacl-poc | uv for package management, ruff for linting | User-specified; uv is faster than pip, ruff replaces flake8+isort+black |
| 2026-03-04 | DEC-TEST-001 | debacl-poc | Mock/fixture-based testing with synthetic telemetry | Real API calls in tests are fragile and require credentials; synthetic data covers edge cases deterministically |

---

## Active Initiatives

### Initiative: DEBACL PoC Build
**Status:** active
**Started:** 2026-03-04
**Goal:** Build a working proof-of-concept that ingests telemetry from multiple sources, correlates expected vs observed IPs, and produces actionable anomaly reports.

> The VPN attack surface problem is well-documented (see README). Organizations already have the telemetry data needed to solve it -- EDR/MDM agents report device IPs, VPN/IdP logs record connection source IPs. DEBACL bridges that gap by correlating these data sources to surface unauthorized access attempts. This PoC proves the concept with real API integrations and structured output.

**Dominant Constraint:** simplicity (PoC must be easy to run, understand, and extend)

#### Goals
- REQ-GOAL-001: Ingest endpoint telemetry from at least 3 sources (CrowdStrike, Intune, Jamf) and normalize to canonical models
- REQ-GOAL-002: Ingest connection/auth telemetry from at least 3 sources (Okta, Entra ID, VPN logs) and normalize to canonical models
- REQ-GOAL-003: Correlate expected IPs (from endpoint telemetry) against observed IPs (from connection events) and flag mismatches
- REQ-GOAL-004: Produce structured findings with severity scoring in JSON and CSV formats
- REQ-GOAL-005: Run entirely locally with no cloud infrastructure dependency (SQLite, mock data mode)

#### Non-Goals
- REQ-NOGO-001: Production-grade deployment (Docker, Kubernetes, CI/CD) -- premature for PoC; separate initiative
- REQ-NOGO-002: Real-time streaming ingestion -- batch processing is sufficient for PoC; streaming adds complexity without proving the concept
- REQ-NOGO-003: Firewall/VPN ACL push automation -- the PoC proves detection, not enforcement; enforcement is a future phase with significant safety implications
- REQ-NOGO-004: Web UI/dashboard -- CLI and API output are sufficient; UI is a separate initiative
- REQ-NOGO-005: DEBACLFI (IdP-focused variant) -- mentioned in README as future work; separate initiative after PoC validates the approach

#### Requirements

**Must-Have (P0)**

- REQ-P0-001: Python project skeleton with uv, ruff, pytest, and proper package structure
  Acceptance: `uv run pytest` succeeds with at least one passing test; `uv run ruff check` passes

- REQ-P0-002: Pydantic models for `EndpointTelemetry` (device_id, hostname, public_ip, source, timestamp, health_status) and `ConnectionEvent` (source_ip, username, destination, event_type, timestamp, source)
  Acceptance: Given valid telemetry data, When instantiated as models, Then validation passes and serialization to JSON round-trips correctly

- REQ-P0-003: Pydantic model for `Finding` (finding_type, severity, source_ip, expected_ips, connection_event, endpoint_telemetry, description, timestamp)
  Acceptance: Given a correlation mismatch, When a Finding is created, Then it contains all context needed to investigate the anomaly

- REQ-P0-004: Abstract base collector interface (`BaseCollector`) with `collect()` method returning canonical models
  Acceptance: Given a new source, When implementing BaseCollector, Then only `collect()` and source-specific config are required

- REQ-P0-005: CrowdStrike Falcon collector -- fetch device public IPs via Falcon API
  Acceptance: Given valid API credentials, When `collect()` is called, Then returns list of `EndpointTelemetry` with public IPs

- REQ-P0-006: Microsoft Intune collector -- fetch managed device IPs via Graph API
  Acceptance: Given valid API credentials, When `collect()` is called, Then returns list of `EndpointTelemetry` with public IPs

- REQ-P0-007: Jamf Pro collector -- fetch managed device IPs via Jamf API
  Acceptance: Given valid API credentials, When `collect()` is called, Then returns list of `EndpointTelemetry` with public IPs

- REQ-P0-008: Okta collector -- fetch authentication events with source IPs via Okta System Log API
  Acceptance: Given valid API token, When `collect()` is called, Then returns list of `ConnectionEvent` with source IPs and usernames

- REQ-P0-009: Microsoft Entra ID collector -- fetch sign-in logs via Graph API
  Acceptance: Given valid API credentials, When `collect()` is called, Then returns list of `ConnectionEvent` with source IPs

- REQ-P0-010: VPN log collector -- parse generic VPN connection logs (CSV/syslog format)
  Acceptance: Given a VPN log file, When `collect()` is called, Then returns list of `ConnectionEvent` with source IPs, usernames, and timestamps

- REQ-P0-011: Correlation engine that compares endpoint IP sets against connection event IPs
  Acceptance: Given endpoint IPs {A, B, C} and connection from IP D, When correlated, Then a Finding is generated with severity based on mismatch type

- REQ-P0-012: JSON and CSV output for findings
  Acceptance: Given a list of Findings, When exported, Then valid JSON and CSV files are produced with all finding fields

- REQ-P0-013: SQLite storage for telemetry and findings with query capability
  Acceptance: Given collected telemetry, When stored, Then data persists across runs and can be queried by time range, source, or IP

- REQ-P0-014: Mock/synthetic data mode for all collectors (no real API credentials needed)
  Acceptance: Given `--mock` flag, When any collector runs, Then it returns realistic synthetic data covering normal and anomalous scenarios

**Nice-to-Have (P1)**

- REQ-P1-001: Configurable severity scoring (thresholds and weights in YAML/TOML config)
- REQ-P1-002: CLI interface with subcommands: `collect`, `correlate`, `report`, `serve`
- REQ-P1-003: FastAPI endpoint for triggering collection and querying findings
- REQ-P1-004: Time-window correlation (only compare IPs within configurable time windows to reduce stale-IP false positives)
- REQ-P1-005: SIEM export format (CEF or JSON lines for Splunk/Elastic ingestion)

**Future Consideration (P2)**

- REQ-P2-001: Firewall ACL push (Palo Alto EDL, Fortinet Fabric Connector) -- design collector output to be consumable as EDL
- REQ-P2-002: Health/posture scoring from EDR data (not just IP, but device compliance state)
- REQ-P2-003: DEBACLFI initiative -- apply same pattern to IdP access policies
- REQ-P2-004: Webhook/alerting integration (Slack, Teams, PagerDuty)

#### Definition of Done

The PoC is done when: (1) all six collectors work in mock mode and produce canonical models, (2) at least CrowdStrike + Okta work with real API credentials, (3) the correlation engine correctly identifies IP mismatches, (4) findings are exported as JSON/CSV with severity scores, (5) `uv run pytest` passes with >80% coverage on core logic, and (6) the tool runs end-to-end from CLI with `--mock` flag.

#### Architectural Decisions

- DEC-MODEL-001: Pydantic v2 for all data models
  Addresses: REQ-P0-002, REQ-P0-003.
  Rationale: Type safety and validation at the data boundary catches malformed telemetry early. Pydantic v2 is significantly faster than v1 and integrates natively with FastAPI. JSON serialization/deserialization is built-in.

- DEC-DATA-001: Polars over pandas for data processing
  Addresses: REQ-P0-011, REQ-P1-004.
  Rationale: Polars provides better type safety (no silent NaN coercion), lazy evaluation for larger datasets, and significantly lower memory usage. The API is more explicit about operations, reducing subtle bugs in IP comparison logic.

- DEC-STORE-001: SQLite via SQLAlchemy for persistence
  Addresses: REQ-P0-013.
  Rationale: SQLite requires zero setup (no database server), stores in a single file, and is sufficient for PoC-scale data. SQLAlchemy provides an ORM layer and a clean migration path to PostgreSQL if the project graduates from PoC.

- DEC-COLLECT-001: Abstract base collector with Strategy pattern
  Addresses: REQ-P0-004, REQ-P0-005 through REQ-P0-010.
  Rationale: Each telemetry source has fundamentally different APIs, auth patterns, and data shapes. The Strategy pattern isolates this complexity: each adapter handles its own API calls and transforms data to canonical models. Adding a new source (e.g., SentinelOne, Zscaler) requires only implementing a new adapter class.

- DEC-CORR-001: Set-based IP correlation with configurable time windows
  Addresses: REQ-P0-011, REQ-P1-004.
  Rationale: The core detection logic is: "Is this connection IP in the set of known-device IPs?" Set membership is O(1) and trivially auditable. Time windows prevent false positives from stale endpoint IP data (e.g., device changed networks hours ago).

- DEC-PKG-001: uv for package management, ruff for linting
  Addresses: REQ-P0-001.
  Rationale: User-specified stack. uv resolves and installs dependencies 10-100x faster than pip. Ruff replaces the flake8+isort+black toolchain with a single, fast Rust-based tool.

- DEC-TEST-001: Mock/fixture-based testing with synthetic telemetry
  Addresses: REQ-P0-014.
  Rationale: Real API calls in tests require credentials, network access, and stable external services. Synthetic data generators produce deterministic, edge-case-covering test fixtures. The same synthetic data mode doubles as the `--mock` flag for demos and evaluation.

#### Phase 1: Foundation
**Status:** completed
**Decision IDs:** DEC-PKG-001, DEC-MODEL-001, DEC-STORE-001
**Requirements:** REQ-P0-001, REQ-P0-002, REQ-P0-003, REQ-P0-004, REQ-P0-013
**Issues:** W1-1 through W1-4 (see Work Items)
**Definition of Done:**
- REQ-P0-001 satisfied: `uv run pytest` passes, `uv run ruff check` passes, package installs cleanly
- REQ-P0-002 satisfied: EndpointTelemetry and ConnectionEvent models validate and serialize correctly
- REQ-P0-003 satisfied: Finding model captures full anomaly context
- REQ-P0-004 satisfied: BaseCollector ABC defined with type hints
- REQ-P0-013 satisfied: SQLite tables created, CRUD operations work for all models

##### Planned Decisions
- DEC-PKG-001: uv + ruff + pytest project scaffold -- Addresses: REQ-P0-001
- DEC-MODEL-001: Pydantic v2 canonical models -- Addresses: REQ-P0-002, REQ-P0-003
- DEC-STORE-001: SQLite via SQLAlchemy -- Addresses: REQ-P0-013

##### Work Items

**W1-1: Project scaffold**
- Initialize with `uv init`, configure `pyproject.toml` with Python 3.11+ requirement
- Add dependencies: pydantic, sqlalchemy, polars, fastapi, uvicorn, httpx, click/typer
- Add dev dependencies: pytest, pytest-cov, ruff, pytest-asyncio
- Create `src/debacl/__init__.py` and package structure per Architecture section
- Configure ruff in pyproject.toml (select = ["E", "F", "I", "UP", "B", "SIM"])
- Configure pytest in pyproject.toml

**W1-2: Canonical data models**
- `src/debacl/models/telemetry.py`: EndpointTelemetry model
  - Fields: device_id (str), hostname (str), public_ip (IPv4Address | IPv6Address), source (Literal["crowdstrike", "intune", "jamf"]), timestamp (datetime), health_status (Optional[str]), raw_data (Optional[dict])
- `src/debacl/models/events.py`: ConnectionEvent model
  - Fields: source_ip (IPv4Address | IPv6Address), username (str), destination (str), event_type (Literal["vpn_connect", "auth_success", "auth_failure"]), timestamp (datetime), source (Literal["okta", "entra", "vpn_log"]), raw_data (Optional[dict])
- `src/debacl/models/findings.py`: Finding model
  - Fields: finding_id (UUID), finding_type (Literal["unmanaged_ip", "ip_mismatch", "unknown_device"]), severity (Literal["critical", "high", "medium", "low", "info"]), source_ip, expected_ips (list), connection_event (ConnectionEvent), matched_telemetry (Optional[EndpointTelemetry]), description (str), timestamp (datetime)
- `src/debacl/models/__init__.py`: re-export all models
- Tests: `tests/test_models.py` -- validation, serialization round-trip, edge cases (invalid IPs, missing fields)

**W1-3: Base collector interface**
- `src/debacl/collectors/base.py`: ABC with `collect() -> list[EndpointTelemetry] | list[ConnectionEvent]`
- Define `CollectorConfig` base model (source name, enabled flag, credentials reference)
- Type hints distinguishing endpoint collectors vs event collectors (generic or union)
- Tests: verify ABC cannot be instantiated, verify interface contract

**W1-4: SQLite storage layer**
- `src/debacl/storage/database.py`: SQLAlchemy engine, session management
- `src/debacl/storage/tables.py`: Table definitions mirroring Pydantic models
- `src/debacl/storage/repository.py`: CRUD operations -- store telemetry, store events, store findings, query by time/source/IP
- Tests: `tests/test_storage.py` -- in-memory SQLite, insert/query/filter operations

##### Critical Files
- `pyproject.toml` -- all project config (dependencies, ruff, pytest, build)
- `src/debacl/models/telemetry.py` -- EndpointTelemetry canonical model
- `src/debacl/models/events.py` -- ConnectionEvent canonical model
- `src/debacl/models/findings.py` -- Finding model (output of correlation)
- `src/debacl/collectors/base.py` -- BaseCollector ABC defining adapter contract

##### Decision Log

| Date | DEC-ID | Initiative | Decision | Rationale |
|------|--------|-----------|----------|-----------|
| 2026-03-05 | DEC-PKG-001 | Phase 1 | uv + ruff + pytest scaffold | Resolved: pyproject.toml created, uv sync verified |
| 2026-03-05 | DEC-MODEL-001 | Phase 1 | Pydantic v2 canonical models | Resolved: EndpointTelemetry, ConnectionEvent, Finding all pass validation + round-trip |
| 2026-03-05 | DEC-STORE-001 | Phase 1 | SQLite via SQLAlchemy 2.0 | Resolved: all 3 repos CRUD-verified with in-memory SQLite |
| 2026-03-05 | DEC-COLLECT-001 | Phase 1 | BaseCollector ABC | Resolved: ABC contract enforced, Generic[T] typed |

#### Phase 2: Collectors
**Status:** planned
**Decision IDs:** DEC-COLLECT-001, DEC-TEST-001
**Requirements:** REQ-P0-005, REQ-P0-006, REQ-P0-007, REQ-P0-008, REQ-P0-009, REQ-P0-010, REQ-P0-014
**Issues:** W2-1 through W2-7 (see Work Items)
**Definition of Done:**
- REQ-P0-005 satisfied: CrowdStrike collector returns EndpointTelemetry from Falcon API (and mock mode)
- REQ-P0-006 satisfied: Intune collector returns EndpointTelemetry from Graph API (and mock mode)
- REQ-P0-007 satisfied: Jamf collector returns EndpointTelemetry from Jamf API (and mock mode)
- REQ-P0-008 satisfied: Okta collector returns ConnectionEvent from System Log API (and mock mode)
- REQ-P0-009 satisfied: Entra collector returns ConnectionEvent from Graph API (and mock mode)
- REQ-P0-010 satisfied: VPN log collector parses CSV/syslog into ConnectionEvent (and mock mode)
- REQ-P0-014 satisfied: All collectors produce realistic synthetic data with `--mock`

##### Planned Decisions
- DEC-COLLECT-001: Strategy pattern per source adapter -- Addresses: REQ-P0-005 through REQ-P0-010
- DEC-TEST-001: Synthetic telemetry fixtures for all sources -- Addresses: REQ-P0-014

##### Work Items

**W2-1: Synthetic data generator**
- `src/debacl/collectors/mock_data.py`: Generate realistic synthetic telemetry
- Include: normal scenarios (known IPs), anomalous scenarios (unknown IPs, IP mismatches), edge cases (IPv6, CGNAT ranges, VPN concentrator IPs)
- Configurable: number of devices, number of events, anomaly ratio
- This is foundational -- all other collector tests depend on it

**W2-2: CrowdStrike Falcon collector**
- `src/debacl/collectors/crowdstrike.py`
- Auth: OAuth2 client credentials (client_id, client_secret)
- API: `GET /devices/queries/devices/v1` then `GET /devices/entities/devices/v2` for device details
- Extract: external_ip field from device entity
- Mock mode: return synthetic EndpointTelemetry
- Tests: mock HTTP responses, verify normalization

**W2-3: Microsoft Intune collector**
- `src/debacl/collectors/intune.py`
- Auth: MSAL client credentials flow (tenant_id, client_id, client_secret)
- API: Microsoft Graph `GET /deviceManagement/managedDevices`
- Extract: device IP from management check-in data
- Mock mode: return synthetic EndpointTelemetry
- Tests: mock HTTP responses, verify normalization

**W2-4: Jamf Pro collector**
- `src/debacl/collectors/jamf.py`
- Auth: API token (bearer) or basic auth
- API: Jamf Pro API `GET /api/v1/computers-inventory`
- Extract: last reported IP from inventory
- Mock mode: return synthetic EndpointTelemetry
- Tests: mock HTTP responses, verify normalization

**W2-5: Okta collector**
- `src/debacl/collectors/okta.py`
- Auth: API token (SSWS header)
- API: `GET /api/v1/logs` with event type filter (user.session.start, user.authentication.*)
- Extract: client.ipAddress, actor.alternateId (username), outcome
- Mock mode: return synthetic ConnectionEvent
- Tests: mock HTTP responses, verify normalization

**W2-6: Microsoft Entra ID collector**
- `src/debacl/collectors/entra.py`
- Auth: MSAL client credentials flow
- API: Microsoft Graph `GET /auditLogs/signIns`
- Extract: ipAddress, userPrincipalName, status
- Mock mode: return synthetic ConnectionEvent
- Tests: mock HTTP responses, verify normalization

**W2-7: VPN log collector**
- `src/debacl/collectors/vpn_log.py`
- Input: CSV file or syslog-formatted log file
- Parse: regex-based extraction for common VPN log formats (Cisco AnyConnect, Palo Alto GlobalProtect, generic CSV)
- Fields: source_ip, username, timestamp, connection_status
- Mock mode: generate synthetic VPN log file, parse it
- Tests: sample log files in `tests/fixtures/`, verify parsing

##### Critical Files
- `src/debacl/collectors/mock_data.py` -- synthetic data generator (dependency for all collector tests)
- `src/debacl/collectors/crowdstrike.py` -- primary EDR integration
- `src/debacl/collectors/okta.py` -- primary IdP integration
- `src/debacl/collectors/vpn_log.py` -- file-based collector (different pattern from API collectors)
- `tests/fixtures/` -- sample API responses and log files

##### Decision Log
<!-- Guardian appends here after phase completion -->

#### Phase 3: Correlation Engine
**Status:** planned
**Decision IDs:** DEC-CORR-001, DEC-DATA-001
**Requirements:** REQ-P0-011, REQ-P1-004
**Issues:** W3-1 through W3-3 (see Work Items)
**Definition of Done:**
- REQ-P0-011 satisfied: Correlation engine produces Findings for unmanaged IPs and IP mismatches
- REQ-P1-004 satisfied (stretch): Time-window filtering reduces false positives from stale data

##### Planned Decisions
- DEC-CORR-001: Set-based IP correlation -- Addresses: REQ-P0-011
- DEC-DATA-001: Polars for data manipulation during correlation -- Addresses: REQ-P0-011, REQ-P1-004

##### Work Items

**W3-1: Core correlation logic**
- `src/debacl/correlation/engine.py`
- Input: list of EndpointTelemetry + list of ConnectionEvent
- Build IP set from endpoint telemetry (known-good IPs)
- For each ConnectionEvent, check if source_ip is in the known-good set
- Classification:
  - `unmanaged_ip`: connection from IP not in any endpoint telemetry
  - `ip_mismatch`: connection username maps to a device, but IP differs from device's reported IP
  - `unknown_device`: IP matches a device, but device health_status is problematic
- Output: list of Finding objects with appropriate severity
- Tests: deterministic scenarios with known inputs/outputs

**W3-2: Severity scoring**
- `src/debacl/correlation/scoring.py`
- Default scoring rules:
  - `critical`: unmanaged IP + successful auth on privileged account
  - `high`: unmanaged IP + successful auth
  - `medium`: IP mismatch (device IP changed recently)
  - `low`: unmanaged IP + failed auth (may be noise)
  - `info`: connection from known IP (baseline data)
- Configurable via TOML/YAML (REQ-P1-001)
- Tests: verify scoring with various scenarios

**W3-3: Time-window correlation (P1)**
- `src/debacl/correlation/windowing.py`
- Only compare endpoint IPs from within a configurable time window (e.g., last 24h)
- Handle: devices that change IPs frequently (mobile, DHCP), CGNAT/shared IP considerations
- Polars lazy frames for efficient time-range filtering
- Tests: scenarios with stale data, IP transitions

##### Critical Files
- `src/debacl/correlation/engine.py` -- core detection logic (the heart of DEBACL)
- `src/debacl/correlation/scoring.py` -- severity classification rules
- `src/debacl/correlation/windowing.py` -- time-window filtering to reduce false positives

##### Decision Log
<!-- Guardian appends here after phase completion -->

#### Phase 4: Output and Reporting
**Status:** planned
**Decision IDs:** DEC-MODEL-001
**Requirements:** REQ-P0-012, REQ-P1-002, REQ-P1-003, REQ-P1-005
**Issues:** W4-1 through W4-4 (see Work Items)
**Definition of Done:**
- REQ-P0-012 satisfied: Findings export as valid JSON and CSV
- REQ-P1-002 satisfied (stretch): CLI with `collect`, `correlate`, `report` subcommands
- REQ-P1-003 satisfied (stretch): FastAPI endpoints for collection and query

##### Planned Decisions
- DEC-MODEL-001: Pydantic serialization for JSON output -- Addresses: REQ-P0-012

##### Work Items

**W4-1: JSON and CSV exporters**
- `src/debacl/output/exporters.py`
- JSON: Pydantic `.model_dump_json()` for individual findings, list serialization for reports
- CSV: field mapping from Finding model to flat CSV columns
- Output directory management (timestamped reports)
- Tests: verify output format, round-trip for JSON, CSV header/row correctness

**W4-2: CLI interface**
- `src/debacl/cli/main.py`
- Commands: `debacl collect [--source <name> | --all] [--mock]`
- Commands: `debacl correlate [--window <hours>] [--since <datetime>]`
- Commands: `debacl report [--format json|csv] [--output <path>]`
- Commands: `debacl serve [--port <port>]` (starts FastAPI)
- Global flags: `--config <path>`, `--verbose`, `--mock`
- Entry point in pyproject.toml: `[project.scripts] debacl = "debacl.cli.main:app"`

**W4-3: FastAPI endpoints (P1)**
- `src/debacl/api/routes.py`
- `POST /collect` -- trigger collection from specified sources
- `GET /findings` -- query findings with filters (severity, time range, source)
- `GET /telemetry` -- query stored endpoint telemetry
- `GET /events` -- query stored connection events
- `GET /health` -- service health check
- Tests: TestClient-based API tests

**W4-4: SIEM export (P1)**
- `src/debacl/output/siem.py`
- CEF (Common Event Format) for ArcSight/QRadar
- JSON lines for Splunk/Elastic
- Syslog forwarding option (UDP/TCP)
- Tests: verify format compliance

##### Critical Files
- `src/debacl/cli/main.py` -- primary user interface
- `src/debacl/output/exporters.py` -- JSON/CSV output generation
- `src/debacl/api/routes.py` -- FastAPI surface

##### Decision Log
<!-- Guardian appends here after phase completion -->

#### Phase 5: Hardening and Integration Testing
**Status:** planned
**Decision IDs:** DEC-TEST-001
**Requirements:** REQ-P0-001 (coverage), REQ-P0-014
**Issues:** W5-1 through W5-4 (see Work Items)
**Definition of Done:**
- Test coverage >80% on core logic (models, collectors, correlation, output)
- End-to-end test: mock collect -> store -> correlate -> report cycle completes
- Error handling: every collector gracefully handles API failures, timeouts, malformed responses
- Configuration: TOML config file with all settings documented

##### Planned Decisions
- DEC-TEST-001: Comprehensive synthetic data scenarios -- Addresses: REQ-P0-014

##### Work Items

**W5-1: End-to-end integration test**
- `tests/test_e2e.py`
- Full pipeline: collect (mock) -> normalize -> store -> correlate -> export
- Verify: correct findings generated, correct severity, correct output format
- Run as part of standard `pytest` suite

**W5-2: Error handling hardening**
- Review all collectors for: connection timeouts, HTTP errors, rate limiting, malformed responses, expired credentials
- Add retry logic with exponential backoff for API collectors (httpx retry)
- Structured error types: `CollectorError`, `AuthenticationError`, `RateLimitError`
- Tests: simulate failure scenarios

**W5-3: Configuration management**
- `src/debacl/config/settings.py`: Pydantic Settings for config loading
- Support: TOML config file, environment variables, CLI overrides (in that precedence order)
- Config fields: source credentials, enabled sources, correlation window, severity thresholds, output directory, log level
- Example config: `config.example.toml`
- Tests: config loading, precedence, validation

**W5-4: Documentation and examples**
- Update README.md with: installation, quickstart, configuration guide
- `docs/architecture.md`: high-level system design (from this plan)
- `docs/adding-a-source.md`: guide for implementing a new collector adapter
- Example: `examples/demo.sh` -- end-to-end demo with mock data

##### Critical Files
- `tests/test_e2e.py` -- end-to-end pipeline validation
- `src/debacl/config/settings.py` -- centralized configuration
- `config.example.toml` -- reference configuration file

##### Decision Log
<!-- Guardian appends here after phase completion -->

#### DEBACL PoC Build Worktree Strategy

Main is sacred. Each phase works in its own worktree:
- **Phase 1:** `C:/Users/Mango/debacl/.worktrees/foundation` on branch `phase-1/foundation`
- **Phase 2:** `C:/Users/Mango/debacl/.worktrees/collectors` on branch `phase-2/collectors`
- **Phase 3:** `C:/Users/Mango/debacl/.worktrees/correlation` on branch `phase-3/correlation`
- **Phase 4:** `C:/Users/Mango/debacl/.worktrees/output` on branch `phase-4/output`
- **Phase 5:** `C:/Users/Mango/debacl/.worktrees/hardening` on branch `phase-5/hardening`

#### DEBACL PoC Build References

- [CrowdStrike Falcon API - Device Management](https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-falcon-api)
- [Microsoft Graph API - Managed Devices](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list)
- [Microsoft Graph API - Sign-in Logs](https://learn.microsoft.com/en-us/graph/api/signin-list)
- [Jamf Pro API Reference](https://developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory)
- [Okta System Log API](https://developer.okta.com/docs/reference/api/system-log/)
- [Pydantic v2 Documentation](https://docs.pydantic.dev/latest/)
- [Polars User Guide](https://docs.pola.rs/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy 2.0 Documentation](https://docs.sqlalchemy.org/en/20/)

---

## Completed Initiatives

| Initiative | Period | Phases | Key Decisions | Archived |
|-----------|--------|--------|---------------|----------|

---

## Parked Issues

| Issue | Description | Reason Parked |
|-------|-------------|---------------|
| DEBACLFI | DEBACL for IdPs -- apply IP allow-listing to identity provider access | Future initiative after PoC validates core approach |
| Firewall Push | Automated ACL push to Palo Alto EDL / Fortinet Fabric Connectors | Requires PoC validation first; significant safety implications |
| Web Dashboard | UI for viewing findings, managing sources, configuring thresholds | Separate initiative; CLI/API sufficient for PoC |
