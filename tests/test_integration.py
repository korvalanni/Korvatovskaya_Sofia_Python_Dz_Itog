"""
Интеграционные тесты (с реальными запросами к NVD NIST API).

Запускаются отдельно: pytest tests/test_integration.py -v
"""

from constants import NvdConfig
from vulners_client import fetch_vulnerabilities, filter_critical


class TestNvdIntegration:
    """Интеграционные тесты NVD NIST API."""

    def test_fetch_returns_results(self):
        result = fetch_vulnerabilities(severity="CRITICAL", limit=5)

        assert isinstance(result, list)
        assert len(result) > 0

    def test_results_have_required_fields(self):
        result = fetch_vulnerabilities(severity="CRITICAL", limit=5)

        assert len(result) > 0, "API вернул пустой результат"
        for vuln in result:
            assert "id" in vuln
            assert "cvss_score" in vuln
            assert isinstance(vuln["cvss_score"], (int, float))
            assert vuln["id"].startswith("CVE-")

    def test_filter_critical_works(self):
        vulns = fetch_vulnerabilities(severity="CRITICAL", limit=10)

        assert len(vulns) > 0, "API вернул пустой результат"
        critical = filter_critical(vulns)

        for vuln in critical:
            assert vuln["cvss_score"] >= NvdConfig.CRITICAL_CVSS_THRESHOLD
