"""Тесты для главного модуля мониторинга угроз."""

import json
from pathlib import Path

import pandas as pd

from threat_monitor import (
    build_report,
    plot_cvss_distribution,
    plot_suspicious_ips,
    respond_to_threats,
    save_report_csv,
    save_report_json,
)

SAMPLE_ALERTS_DF = pd.DataFrame(
    [
        {
            "timestamp": "t1",
            "src_ip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "proto": "TCP",
            "signature": "sig1",
            "severity": 1,
            "category": "Malware",
        },
        {
            "timestamp": "t2",
            "src_ip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "proto": "TCP",
            "signature": "sig2",
            "severity": 1,
            "category": "Malware",
        },
        {
            "timestamp": "t3",
            "src_ip": "3.3.3.3",
            "dest_ip": "4.4.4.4",
            "proto": "TCP",
            "signature": "sig3",
            "severity": 2,
            "category": "Scan",
        },
    ]
)

SAMPLE_SUSPICIOUS_IPS = [
    {"ip": "1.1.1.1", "alert_count": 5},
    {"ip": "3.3.3.3", "alert_count": 2},
]

SAMPLE_SUSPICIOUS_DNS = [
    {"ip": "1.1.1.1", "query_count": 10, "domains": ["evil.com", "bad.xyz"]},
]

SAMPLE_VULNS = [
    {
        "id": "CVE-2024-1234",
        "cvss_score": 9.8,
        "title": "Critical RCE",
        "description": "RCE vuln",
        "published": "2024-01-15",
        "type": "cve",
    },
    {
        "id": "CVE-2024-5678",
        "cvss_score": 7.5,
        "title": "SQL Injection",
        "description": "SQLi vuln",
        "published": "2024-02-20",
        "type": "cve",
    },
]


class TestRespondToThreats:
    """Тесты реагирования на угрозы."""

    def test_blocks_suspicious_ips(self, capsys):
        actions = respond_to_threats(SAMPLE_SUSPICIOUS_IPS, [], [])

        assert any(a["action"] == "block_ip" for a in actions)
        output = capsys.readouterr().out
        assert "1.1.1.1" in output
        assert "чёрный список" in output

    def test_notifies_dns_anomaly(self, capsys):
        actions = respond_to_threats([], SAMPLE_SUSPICIOUS_DNS, [])

        assert any(a["action"] == "notify" for a in actions)
        output = capsys.readouterr().out
        assert "Уведомление" in output

    def test_alerts_on_vulnerabilities(self, capsys):
        actions = respond_to_threats([], [], SAMPLE_VULNS)

        assert any(a["action"] == "alert_vulnerability" for a in actions)
        output = capsys.readouterr().out
        assert "CVE-2024-1234" in output

    def test_no_threats_message(self, capsys):
        actions = respond_to_threats([], [], [])

        assert actions == []
        output = capsys.readouterr().out
        assert "не обнаружено" in output

    def test_no_duplicate_ip_blocks(self):
        ips = [{"ip": "1.1.1.1", "alert_count": 5}]
        dns = [{"ip": "1.1.1.1", "query_count": 10, "domains": ["a.com"]}]

        actions = respond_to_threats(ips, dns, [])

        block_actions = [a for a in actions if a["action"] == "block_ip"]
        assert len(block_actions) == 1


class TestBuildReport:
    """Тесты формирования отчёта."""

    def test_report_structure(self):
        report = build_report(
            SAMPLE_ALERTS_DF,
            SAMPLE_SUSPICIOUS_IPS,
            SAMPLE_SUSPICIOUS_DNS,
            SAMPLE_VULNS,
            [],
        )

        assert "report_date" in report
        assert "summary" in report
        assert "suspicious_ips" in report
        assert "top_vulnerabilities" in report
        assert "response_actions" in report

    def test_summary_counts(self):
        report = build_report(
            SAMPLE_ALERTS_DF,
            SAMPLE_SUSPICIOUS_IPS,
            SAMPLE_SUSPICIOUS_DNS,
            SAMPLE_VULNS,
            [{"action": "test"}],
        )

        assert report["summary"]["total_alerts"] == 3
        assert report["summary"]["suspicious_ips_count"] == 2
        assert report["summary"]["critical_vulnerabilities"] == 2
        assert report["summary"]["response_actions_taken"] == 1

    def test_empty_data(self):
        report = build_report(pd.DataFrame(), [], [], [], [])

        assert report["summary"]["total_alerts"] == 0


class TestSaveReportJson:
    """Тесты сохранения JSON-отчёта."""

    def test_creates_file(self, tmp_path):
        filepath = str(tmp_path / "report.json")
        report = {"test": "data"}

        result = save_report_json(report, filepath)

        assert result is True
        assert Path(filepath).exists()

    def test_valid_json_content(self, tmp_path):
        filepath = str(tmp_path / "report.json")
        report = {"key": "value", "number": 42}

        save_report_json(report, filepath)

        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        assert data["key"] == "value"

    def test_creates_parent_dirs(self, tmp_path):
        filepath = str(tmp_path / "sub" / "dir" / "report.json")

        result = save_report_json({"test": True}, filepath)

        assert result is True


class TestSaveReportCsv:
    """Тесты сохранения CSV-отчёта."""

    def test_creates_file(self, tmp_path):
        filepath = str(tmp_path / "report.csv")
        report = {
            "suspicious_ips": [{"ip": "1.1.1.1", "alert_count": 5}],
            "suspicious_dns": [],
            "top_vulnerabilities": [],
        }

        result = save_report_csv(report, filepath)

        assert result is True
        assert Path(filepath).exists()

    def test_csv_content(self, tmp_path):
        filepath = str(tmp_path / "report.csv")
        report = {
            "suspicious_ips": [{"ip": "1.1.1.1", "alert_count": 5}],
            "suspicious_dns": [],
            "top_vulnerabilities": [
                {"id": "CVE-1", "cvss_score": 9.8},
            ],
        }

        save_report_csv(report, filepath)

        df = pd.read_csv(filepath)
        assert len(df) == 2
        assert "suspicious_ip" in df["type"].values


class TestPlotSuspiciousIps:
    """Тесты построения графиков."""

    def test_creates_png(self, tmp_path):
        filepath = str(tmp_path / "chart.png")

        result = plot_suspicious_ips(SAMPLE_SUSPICIOUS_IPS, filepath)

        assert result is True
        assert Path(filepath).exists()

    def test_empty_data_returns_false(self, tmp_path):
        filepath = str(tmp_path / "chart.png")

        result = plot_suspicious_ips([], filepath)

        assert result is False


class TestPlotCvssDistribution:
    """Тесты построения графика CVSS."""

    def test_creates_png(self, tmp_path):
        filepath = str(tmp_path / "cvss.png")

        result = plot_cvss_distribution(SAMPLE_VULNS, filepath)

        assert result is True
        assert Path(filepath).exists()

    def test_empty_data_returns_false(self, tmp_path):
        filepath = str(tmp_path / "cvss.png")

        result = plot_cvss_distribution([], filepath)

        assert result is False
