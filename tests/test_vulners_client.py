"""Тесты для модуля работы с Vulners API."""

import requests.exceptions
import responses

from constants import VulnersConfig
from vulners_client import fetch_vulnerabilities, filter_critical, get_api_key

MOCK_VULNERS_RESPONSE = {
    "result": "OK",
    "data": {
        "search": [
            {
                "_source": {
                    "id": "CVE-2024-1234",
                    "title": "Critical RCE in Example Software",
                    "cvss": {"score": 9.8},
                    "description": "Remote code execution vulnerability",
                    "published": "2024-01-15",
                    "type": "cve",
                }
            },
            {
                "_source": {
                    "id": "CVE-2024-5678",
                    "title": "SQL Injection in Web Framework",
                    "cvss": {"score": 7.5},
                    "description": "SQL injection allows data access",
                    "published": "2024-02-20",
                    "type": "cve",
                }
            },
            {
                "_source": {
                    "id": "CVE-2024-9999",
                    "title": "Low severity info disclosure",
                    "cvss": {"score": 3.1},
                    "description": "Information disclosure via error messages",
                    "published": "2024-03-01",
                    "type": "cve",
                }
            },
        ]
    },
}


class TestGetApiKey:
    """Тесты получения API ключа."""

    def test_key_from_env(self, monkeypatch):
        monkeypatch.setenv(VulnersConfig.API_KEY_ENV_VAR, "test_key_123")

        result = get_api_key()

        assert result == "test_key_123"

    def test_missing_key(self, monkeypatch):
        monkeypatch.delenv(VulnersConfig.API_KEY_ENV_VAR, raising=False)

        result = get_api_key()

        assert result is None

    def test_empty_key(self, monkeypatch):
        monkeypatch.setenv(VulnersConfig.API_KEY_ENV_VAR, "")

        result = get_api_key()

        assert result is None


class TestFetchVulnerabilities:
    """Тесты запроса уязвимостей."""

    @responses.activate
    def test_successful_fetch(self):
        url = f"{VulnersConfig.BASE_URL}{VulnersConfig.SEARCH_ENDPOINT}"
        responses.add(responses.POST, url, json=MOCK_VULNERS_RESPONSE, status=200)

        result = fetch_vulnerabilities("test_key")

        assert len(result) == 3
        assert result[0]["id"] == "CVE-2024-1234"
        assert result[0]["cvss_score"] == 9.8

    @responses.activate
    def test_api_error_response(self):
        url = f"{VulnersConfig.BASE_URL}{VulnersConfig.SEARCH_ENDPOINT}"
        responses.add(
            responses.POST,
            url,
            json={"result": "error", "data": {"error": "Invalid API key"}},
            status=200,
        )

        result = fetch_vulnerabilities("bad_key")

        assert result == []

    @responses.activate
    def test_network_error(self, capsys):
        url = f"{VulnersConfig.BASE_URL}{VulnersConfig.SEARCH_ENDPOINT}"
        responses.add(
            responses.POST,
            url,
            body=requests.exceptions.ConnectionError("timeout"),
        )

        result = fetch_vulnerabilities("test_key")

        assert result == []

    @responses.activate
    def test_http_error(self):
        url = f"{VulnersConfig.BASE_URL}{VulnersConfig.SEARCH_ENDPOINT}"
        responses.add(responses.POST, url, status=500)

        result = fetch_vulnerabilities("test_key")

        assert result == []

    @responses.activate
    def test_parses_all_fields(self):
        url = f"{VulnersConfig.BASE_URL}{VulnersConfig.SEARCH_ENDPOINT}"
        responses.add(responses.POST, url, json=MOCK_VULNERS_RESPONSE, status=200)

        result = fetch_vulnerabilities("test_key")

        vuln = result[0]
        assert "id" in vuln
        assert "title" in vuln
        assert "cvss_score" in vuln
        assert "description" in vuln
        assert "published" in vuln


class TestFilterCritical:
    """Тесты фильтрации критических уязвимостей."""

    def test_filter_default_threshold(self):
        vulns = [
            {"id": "CVE-1", "cvss_score": 9.8},
            {"id": "CVE-2", "cvss_score": 7.5},
            {"id": "CVE-3", "cvss_score": 3.1},
        ]

        result = filter_critical(vulns)

        assert len(result) == 2
        assert result[0]["cvss_score"] == 9.8

    def test_filter_custom_threshold(self):
        vulns = [
            {"id": "CVE-1", "cvss_score": 9.8},
            {"id": "CVE-2", "cvss_score": 7.5},
            {"id": "CVE-3", "cvss_score": 3.1},
        ]

        result = filter_critical(vulns, threshold=9.0)

        assert len(result) == 1

    def test_filter_empty_list(self):
        result = filter_critical([])

        assert result == []

    def test_sorted_by_score_desc(self):
        vulns = [
            {"id": "CVE-1", "cvss_score": 7.0},
            {"id": "CVE-2", "cvss_score": 9.5},
            {"id": "CVE-3", "cvss_score": 8.2},
        ]

        result = filter_critical(vulns)

        scores = [v["cvss_score"] for v in result]
        assert scores == sorted(scores, reverse=True)
