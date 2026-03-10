"""
Интеграционные тесты (требуют реальный API-ключ Vulners).

Запускаются отдельно: pytest tests/test_integration.py -v
"""

import os

import pytest

from constants import VulnersConfig
from vulners_client import fetch_vulnerabilities, filter_critical

pytestmark = pytest.mark.skipif(
    not os.environ.get(VulnersConfig.API_KEY_ENV_VAR),
    reason=f"Требуется {VulnersConfig.API_KEY_ENV_VAR} для интеграционных тестов",
)


class TestVulnersIntegration:
    """Интеграционные тесты Vulners API."""

    @pytest.fixture
    def api_key(self):
        return os.environ[VulnersConfig.API_KEY_ENV_VAR]

    def test_fetch_returns_results(self, api_key):
        result = fetch_vulnerabilities(api_key, limit=5)

        assert isinstance(result, list)
        assert len(result) > 0

    def test_results_have_cvss(self, api_key):
        result = fetch_vulnerabilities(api_key, limit=5)

        for vuln in result:
            assert "cvss_score" in vuln
            assert isinstance(vuln["cvss_score"], (int, float))

    def test_filter_critical_works(self, api_key):
        vulns = fetch_vulnerabilities(api_key, limit=10)
        critical = filter_critical(vulns)

        for vuln in critical:
            assert vuln["cvss_score"] >= VulnersConfig.CRITICAL_CVSS_THRESHOLD
