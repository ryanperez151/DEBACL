"""CLI acceptance tests: provider response -> canonical model -> SQLite -> report."""

import json
from datetime import UTC, datetime, timedelta, timezone

from typer.testing import CliRunner

from debacl.cli.main import app
from debacl.config import DebacleSettings
from debacl.storage.database import get_engine, init_db
from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

runner = CliRunner()
_CS_TOKEN_URL = "https://api.crowdstrike.com/oauth2/token"
_CS_IDS_URL = "https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0"
_CS_DETAILS_URL = "https://api.crowdstrike.com/devices/entities/devices/v2"
_OKTA_LOGS_URL = (
    'https://test.okta.com/api/v1/logs?filter=eventType+eq+"user.session.start"&limit=1000'
)
_INTUNE_TOKEN_URL = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"
_INTUNE_DEVICES_URL = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"


def _settings(tmp_path, monkeypatch, **overrides):
    defaults = dict(
        db_path=str(tmp_path / "fresh.db"),
        crowdstrike_client_id="fixture-id",
        crowdstrike_client_secret="fixture-secret",
        okta_domain="https://test.okta.com",
        okta_api_token="fixture-token",
        azure_tenant_id="test-tenant",
        azure_client_id="fixture-id",
        azure_client_secret="fixture-secret",
    )
    defaults.update(overrides)
    settings = DebacleSettings(**defaults)
    monkeypatch.setattr("debacl.config.get_settings", lambda: settings)
    return settings


def _repos(settings):
    engine = get_engine(f"sqlite:///{settings.db_path}")
    init_db(engine)
    return TelemetryRepository(engine), EventRepository(engine), FindingRepository(engine)


def _crowdstrike_responses(httpx_mock, records):
    httpx_mock.add_response(
        method="POST", url=_CS_TOKEN_URL, status_code=201, json={"access_token": "fixture"}
    )
    httpx_mock.add_response(
        method="GET",
        url=_CS_IDS_URL,
        json={
            "resources": [record["device_id"] for record in records],
            "meta": {"pagination": {"total": len(records)}},
        },
    )
    if records:
        httpx_mock.add_response(method="POST", url=_CS_DETAILS_URL, json={"resources": records})


def test_clean_database_collect_correlate_report_with_mocked_provider_responses(
    tmp_path, monkeypatch, httpx_mock
):
    settings = _settings(tmp_path, monkeypatch)
    assert not (tmp_path / "fresh.db").exists()
    now = datetime.now(UTC).replace(microsecond=0)
    source_time = now.astimezone(timezone(timedelta(hours=-4))).isoformat()
    devices = [
        {
            "device_id": "managed-v4",
            "hostname": "workstation-a",
            "external_ip": "203.0.113.10",
            "last_seen": source_time,
            "status": "normal",
        },
        {
            "device_id": "managed-v6",
            "hostname": "workstation-b",
            "external_ip": "2001:db8::10",
            "last_seen": source_time,
            "status": "normal",
        },
    ]
    events = [
        {
            "published": now.isoformat(),
            "actor": {"alternateId": "alice@example.test"},
            "client": {"ipAddress": "203.0.113.10"},
            "outcome": {"result": "SUCCESS"},
        },
        {
            "published": now.isoformat(),
            "actor": {"alternateId": "bob@example.test"},
            "client": {"ipAddress": "2001:db8::99"},
            "outcome": {"result": "SUCCESS"},
        },
    ]

    for expected_saved in (2, 0):
        _crowdstrike_responses(httpx_mock, devices)
        result = runner.invoke(app, ["collect", "--source", "crowdstrike", "--no-mock"])
        assert result.exit_code == 0, result.output
        assert f"persisted {expected_saved}" in result.output

        httpx_mock.add_response(method="GET", url=_OKTA_LOGS_URL, json=events)
        result = runner.invoke(app, ["collect", "--source", "okta", "--no-mock"])
        assert result.exit_code == 0, result.output
        assert f"persisted {expected_saved}" in result.output

    t_repo, e_repo, f_repo = _repos(settings)
    telemetry = t_repo.get_all()
    stored_events = e_repo.get_all()
    assert len(telemetry) == 2
    assert len(stored_events) == 2
    assert {str(item.public_ip) for item in telemetry} == {"203.0.113.10", "2001:db8::10"}
    assert telemetry[0].source == "crowdstrike"
    assert telemetry[0].raw_data == devices[0]
    assert telemetry[0].timestamp == now
    assert stored_events[1].source == "okta"
    assert stored_events[1].raw_data == events[1]
    assert stored_events[1].timestamp == now

    offset_cutoff = (now - timedelta(minutes=1)).astimezone(timezone(timedelta(hours=5)))
    result = runner.invoke(
        app, ["correlate", "--window", "24", "--since", offset_cutoff.isoformat()]
    )
    assert result.exit_code == 0, result.output
    findings = f_repo.get_all()
    assert len(findings) == 1
    assert str(findings[0].source_ip) == "2001:db8::99"
    assert findings[0].finding_type == "unmanaged_ip"

    output_dir = tmp_path / "out"
    result = runner.invoke(app, ["report", "--format", "json", "--output", str(output_dir)])
    assert result.exit_code == 0, result.output
    report = json.loads(next(output_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert len(report) == 1
    assert report[0]["source_ip"] == "2001:db8::99"
    assert report[0]["connection_event"]["raw_data"] == events[1]


def test_intune_skips_missing_ip_without_using_mac_and_exits_incomplete(
    tmp_path, monkeypatch, httpx_mock
):
    settings = _settings(tmp_path, monkeypatch)
    now = datetime.now(UTC).isoformat()
    httpx_mock.add_response(method="POST", url=_INTUNE_TOKEN_URL, json={"access_token": "fixture"})
    httpx_mock.add_response(
        method="GET",
        url=_INTUNE_DEVICES_URL,
        json={
            "value": [
                {
                    "id": "missing-ip",
                    "deviceName": "no-public-ip",
                    "wiFiMacAddress": "00:11:22:33:44:55",
                    "lastSyncDateTime": now,
                },
                {
                    "id": "valid-ip",
                    "deviceName": "has-public-ip",
                    "publicIpAddress": "2001:db8::20",
                    "lastSyncDateTime": now,
                },
            ]
        },
    )

    result = runner.invoke(app, ["collect", "--source", "intune", "--no-mock"])
    assert result.exit_code == 1
    assert "persisted 1" in result.output
    assert "skipped 1" in result.output
    telemetry = _repos(settings)[0].get_all()
    assert len(telemetry) == 1
    assert str(telemetry[0].public_ip) == "2001:db8::20"


def test_invalid_ip_or_provider_error_does_not_claim_success_or_persist(
    tmp_path, monkeypatch, httpx_mock
):
    settings = _settings(tmp_path, monkeypatch)
    _crowdstrike_responses(
        httpx_mock,
        [
            {
                "device_id": "bad-ip",
                "external_ip": "00:11:22:33:44:55",
                "last_seen": datetime.now(UTC).isoformat(),
            }
        ],
    )
    result = runner.invoke(app, ["collect", "--source", "crowdstrike", "--no-mock"])
    assert result.exit_code == 1
    assert "skipped 1" in result.output
    assert "No usable records returned" in result.output
    assert "00:11" not in result.output
    assert _repos(settings)[0].get_all() == []

    httpx_mock.add_response(
        method="POST", url=_CS_TOKEN_URL, status_code=401, text="sensitive-response-body"
    )
    result = runner.invoke(app, ["collect", "--source", "crowdstrike", "--no-mock"])
    assert result.exit_code == 1
    assert "sensitive-response-body" not in result.output
    assert _repos(settings)[0].get_all() == []


def test_empty_provider_response_and_no_save(tmp_path, monkeypatch, httpx_mock):
    settings = _settings(tmp_path, monkeypatch)
    _crowdstrike_responses(httpx_mock, [])
    result = runner.invoke(app, ["collect", "--source", "crowdstrike", "--no-mock"])
    assert result.exit_code == 0, result.output
    assert "No usable records returned" in result.output
    assert _repos(settings)[0].get_all() == []

    # The no-save path invokes a real collector but never opens the database.
    other_settings = _settings(tmp_path, monkeypatch, db_path=str(tmp_path / "not-created.db"))
    assert other_settings.db_path.endswith("not-created.db")
    _crowdstrike_responses(httpx_mock, [])
    result = runner.invoke(app, ["collect", "--source", "crowdstrike", "--no-mock", "--no-save"])
    assert result.exit_code == 0, result.output
    assert "not saved" in result.output
    assert not (tmp_path / "not-created.db").exists()


def test_live_configuration_and_unknown_source_fail_without_provider_requests(
    tmp_path, monkeypatch, httpx_mock
):
    _settings(
        tmp_path,
        monkeypatch,
        crowdstrike_client_id="",
        crowdstrike_client_secret="",
    )
    result = runner.invoke(app, ["collect", "--source", "crowdstrike", "--no-mock"])
    assert result.exit_code == 1
    assert "DEBACL_CROWDSTRIKE_CLIENT_ID" in result.output
    assert httpx_mock.get_requests() == []

    result = runner.invoke(app, ["collect", "--source", "typo", "--no-mock"])
    assert result.exit_code == 1
    assert "Unknown source" in result.output
    assert httpx_mock.get_requests() == []

    result = runner.invoke(app, ["collect", "--all", "--no-mock"])
    assert result.exit_code == 1
    assert "No sources are enabled" in result.output
    assert httpx_mock.get_requests() == []


def test_all_mock_sources_use_collectors_and_persist_both_model_types(tmp_path, monkeypatch):
    settings = _settings(tmp_path, monkeypatch)
    result = runner.invoke(app, ["collect", "--all", "--mock"])
    assert result.exit_code == 0, result.output
    for source in ("crowdstrike", "intune", "jamf", "okta", "entra", "vpn_log"):
        assert "Collected" in result.output
        assert f"from {source}" in result.output
    telemetry, events, _ = _repos(settings)
    assert telemetry.get_all()
    assert events.get_all()


def test_repeated_syslog_collect_preserves_distinct_lines_without_replay_duplicates(
    tmp_path, monkeypatch
):
    log_path = tmp_path / "vpn.log"
    log_path.write_text(
        "src=203.0.113.10 user=alice connected\nsrc=203.0.113.10 user=alice connected\n",
        encoding="utf-8",
    )
    settings = _settings(tmp_path, monkeypatch, vpn_log_path=str(log_path), vpn_log_format="syslog")

    for expected_saved in (2, 0):
        result = runner.invoke(app, ["collect", "--source", "vpn_log", "--no-mock"])
        assert result.exit_code == 0, result.output
        assert f"persisted {expected_saved}" in result.output

    events = _repos(settings)[1].get_all()
    assert len(events) == 2
    assert {event.raw_data["line_number"] for event in events} == {1, 2}
    assert all(event.raw_data["timestamp_basis"] == "collection_time" for event in events)
