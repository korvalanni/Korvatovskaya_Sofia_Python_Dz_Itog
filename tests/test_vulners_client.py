"""Тесты для модуля работы с NVD NIST API."""

import requests.exceptions
import responses

from constants import NvdConfig
from vulners_client import fetch_vulnerabilities, filter_critical

MOCK_NVD_RESPONSE = {
    "resultsPerPage": 3,
    "startIndex": 0,
    "totalResults": 3,
    "format": "NVD_CVE",
    "version": "2.0",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Remote code execution vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "published": "2024-01-15T00:00:00.000",
            }
        },
        {
            "cve": {
                "id": "CVE-2024-5678",
                "descriptions": [{"lang": "en", "value": "SQL injection allows data access"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
                "published": "2024-02-20T00:00:00.000",
            }
        },
        {
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [
                    {"lang": "en", "value": "Information disclosure via error messages"}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 3.1,
                                "baseSeverity": "LOW",
                            }
                        }
                    ]
                },
                "published": "2024-03-01T00:00:00.000",
            }
        },
    ],
}


class TestFetchVulnerabilities:
    """Тесты запроса уязвимостей через NVD API."""

    @responses.activate
    def test_successful_fetch(self):
        responses.add(responses.GET, NvdConfig.BASE_URL, json=MOCK_NVD_RESPONSE, status=200)

        result = fetch_vulnerabilities()

        assert len(result) == 3
        assert result[0]["id"] == "CVE-2024-1234"
        assert result[0]["cvss_score"] == 9.8

    @responses.activate
    def test_empty_response(self):
        responses.add(
            responses.GET,
            NvdConfig.BASE_URL,
            json={"vulnerabilities": [], "totalResults": 0},
            status=200,
        )

        result = fetch_vulnerabilities()

        assert result == []

    @responses.activate
    def test_network_error(self, capsys):
        responses.add(
            responses.GET,
            NvdConfig.BASE_URL,
            body=requests.exceptions.ConnectionError("timeout"),
        )

        result = fetch_vulnerabilities()

        assert result == []

    @responses.activate
    def test_http_error(self):
        responses.add(responses.GET, NvdConfig.BASE_URL, status=500)

        result = fetch_vulnerabilities()

        assert result == []

    @responses.activate
    def test_parses_all_fields(self):
        responses.add(responses.GET, NvdConfig.BASE_URL, json=MOCK_NVD_RESPONSE, status=200)

        result = fetch_vulnerabilities()

        vuln = result[0]
        assert "id" in vuln
        assert "title" in vuln
        assert "cvss_score" in vuln
        assert "description" in vuln
        assert "published" in vuln

    @responses.activate
    def test_extracts_english_description(self):
        responses.add(responses.GET, NvdConfig.BASE_URL, json=MOCK_NVD_RESPONSE, status=200)

        result = fetch_vulnerabilities()

        assert result[0]["description"] == "Remote code execution vulnerability"

    @responses.activate
    def test_request_params(self):
        responses.add(responses.GET, NvdConfig.BASE_URL, json=MOCK_NVD_RESPONSE, status=200)

        fetch_vulnerabilities(severity="HIGH", limit=5)

        assert "cvssV3Severity=HIGH" in responses.calls[0].request.url
        assert "resultsPerPage=5" in responses.calls[0].request.url


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
