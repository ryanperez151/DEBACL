"""
Tests for SeverityScorer and is_privileged helper.

Verifies all documented severity combinations and the privileged-account
escalation rule.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Address

from debacl.correlation.scoring import SeverityScorer, is_privileged
from debacl.models.events import ConnectionEvent

_NOW = datetime.now(UTC)

_DEFAULT_PATTERNS = ["admin", "svc-", "root", "system"]


def _event(
    event_type: str = "auth_success",
    username: str = "john.doe@corp.com",
) -> ConnectionEvent:
    return ConnectionEvent(
        source_ip=IPv4Address("10.0.0.1"),
        username=username,
        destination="corp.vpn",
        event_type=event_type,  # type: ignore[arg-type]
        timestamp=_NOW,
        source="okta",
    )


# ---------------------------------------------------------------------------
# is_privileged
# ---------------------------------------------------------------------------


class TestIsPrivileged:
    def test_admin_is_privileged(self) -> None:
        assert is_privileged("admin@corp.com", _DEFAULT_PATTERNS) is True

    def test_john_doe_is_not_privileged(self) -> None:
        assert is_privileged("john.doe@corp.com", _DEFAULT_PATTERNS) is False

    def test_svc_backup_is_privileged(self) -> None:
        assert is_privileged("svc-backup@corp.com", _DEFAULT_PATTERNS) is True

    def test_root_is_privileged(self) -> None:
        assert is_privileged("root@corp.com", _DEFAULT_PATTERNS) is True

    def test_system_account_is_privileged(self) -> None:
        assert is_privileged("system.service@corp.com", _DEFAULT_PATTERNS) is True

    def test_case_insensitive_match(self) -> None:
        assert is_privileged("ADMIN@CORP.COM", _DEFAULT_PATTERNS) is True

    def test_empty_patterns_never_privileged(self) -> None:
        assert is_privileged("admin@corp.com", []) is False

    def test_partial_match_in_middle(self) -> None:
        # "svc-" appears in the middle of "svc-deploy-prod@corp.com"
        assert is_privileged("svc-deploy-prod@corp.com", _DEFAULT_PATTERNS) is True

    def test_regular_user_names(self) -> None:
        for username in ["alice@corp.com", "bob.smith@corp.com", "carol123@example.org"]:
            assert is_privileged(username, _DEFAULT_PATTERNS) is False


# ---------------------------------------------------------------------------
# SeverityScorer — ip_mismatch
# ---------------------------------------------------------------------------


class TestSeverityScorerIpMismatch:
    def test_ip_mismatch_auth_success_is_medium(self) -> None:
        scorer = SeverityScorer()
        assert scorer.score("ip_mismatch", _event("auth_success")) == "medium"

    def test_ip_mismatch_auth_failure_is_low(self) -> None:
        scorer = SeverityScorer()
        assert scorer.score("ip_mismatch", _event("auth_failure")) == "low"

    def test_ip_mismatch_vpn_connect_is_high(self) -> None:
        scorer = SeverityScorer()
        assert scorer.score("ip_mismatch", _event("vpn_connect")) == "high"


# ---------------------------------------------------------------------------
# SeverityScorer — unmanaged_ip + auth_success, non-privileged → high
# ---------------------------------------------------------------------------


class TestSeverityScorerUnmanagedHigh:
    def test_unmanaged_auth_success_non_privileged_is_high(self) -> None:
        scorer = SeverityScorer()
        result = scorer.score(
            "unmanaged_ip",
            _event("auth_success", username="john.doe@corp.com"),
            privileged_patterns=_DEFAULT_PATTERNS,
        )
        assert result == "high"

    def test_unmanaged_auth_failure_is_low(self) -> None:
        scorer = SeverityScorer()
        result = scorer.score(
            "unmanaged_ip",
            _event("auth_failure", username="john.doe@corp.com"),
            privileged_patterns=_DEFAULT_PATTERNS,
        )
        assert result == "low"


# ---------------------------------------------------------------------------
# SeverityScorer — unmanaged_ip + auth_success, privileged → critical
# ---------------------------------------------------------------------------


class TestSeverityScorerUnmanagedCritical:
    def test_unmanaged_auth_success_admin_is_critical(self) -> None:
        scorer = SeverityScorer()
        result = scorer.score(
            "unmanaged_ip",
            _event("auth_success", username="admin@corp.com"),
            privileged_patterns=_DEFAULT_PATTERNS,
        )
        assert result == "critical"

    def test_unmanaged_auth_success_svc_account_is_critical(self) -> None:
        scorer = SeverityScorer()
        result = scorer.score(
            "unmanaged_ip",
            _event("auth_success", username="svc-backup@corp.com"),
            privileged_patterns=_DEFAULT_PATTERNS,
        )
        assert result == "critical"

    def test_unmanaged_vpn_connect_always_critical(self) -> None:
        """vpn_connect for unmanaged_ip is critical regardless of privilege."""
        scorer = SeverityScorer()
        # Non-privileged VPN connect — still critical per default rules
        result = scorer.score(
            "unmanaged_ip",
            _event("vpn_connect", username="john.doe@corp.com"),
            privileged_patterns=_DEFAULT_PATTERNS,
        )
        assert result == "critical"

    def test_unmanaged_auth_failure_privileged_stays_low(self) -> None:
        """Escalation only applies to successful connections, not failures."""
        scorer = SeverityScorer()
        result = scorer.score(
            "unmanaged_ip",
            _event("auth_failure", username="admin@corp.com"),
            privileged_patterns=_DEFAULT_PATTERNS,
        )
        assert result == "low"


# ---------------------------------------------------------------------------
# SeverityScorer — info finding_type
# ---------------------------------------------------------------------------


class TestSeverityScorerInfo:
    def test_info_finding_type_always_info_severity(self) -> None:
        scorer = SeverityScorer()
        assert scorer.score("info", _event("auth_success")) == "info"
        assert scorer.score("info", _event("auth_failure")) == "info"
        assert scorer.score("info", _event("vpn_connect")) == "info"


# ---------------------------------------------------------------------------
# SeverityScorer — custom rules override
# ---------------------------------------------------------------------------


class TestSeverityScorerCustomRules:
    def test_custom_rules_override_defaults(self) -> None:
        custom = {"unmanaged_ip": {"auth_failure": "high"}}
        scorer = SeverityScorer(rules=custom)
        result = scorer.score("unmanaged_ip", _event("auth_failure"))
        assert result == "high"

    def test_non_overridden_rules_preserved(self) -> None:
        custom = {"unmanaged_ip": {"auth_failure": "medium"}}
        scorer = SeverityScorer(rules=custom)
        # auth_success for non-privileged should still use default "high"
        result = scorer.score(
            "unmanaged_ip",
            _event("auth_success", username="john@corp.com"),
            privileged_patterns=_DEFAULT_PATTERNS,
        )
        assert result == "high"

    def test_unknown_finding_type_returns_info(self) -> None:
        scorer = SeverityScorer()
        result = scorer.score("brand_new_type", _event("auth_success"))
        assert result == "info"
