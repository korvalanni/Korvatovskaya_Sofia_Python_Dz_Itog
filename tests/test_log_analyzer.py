"""Тесты для модуля анализа логов Suricata."""

import json

import pandas as pd

from log_analyzer import (
    extract_alerts,
    extract_dns_queries,
    find_suspicious_dns,
    find_suspicious_ips,
    load_logs,
)

SAMPLE_EVENTS = [
    {
        "timestamp": "2026-03-10T08:12:01.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.105",
        "dest_ip": "10.0.0.1",
        "proto": "TCP",
        "alert": {
            "signature": "ET MALWARE Possible Malicious Payload",
            "severity": 1,
            "category": "Malware",
        },
    },
    {
        "timestamp": "2026-03-10T08:12:05.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.105",
        "dest_ip": "10.0.0.1",
        "proto": "TCP",
        "alert": {
            "signature": "ET TROJAN C2 Communication",
            "severity": 1,
            "category": "Malware",
        },
    },
    {
        "timestamp": "2026-03-10T08:13:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.10.10.55",
        "dest_ip": "192.168.1.1",
        "proto": "TCP",
        "alert": {
            "signature": "ET SCAN Nmap Detected",
            "severity": 3,
            "category": "Attempted Information Leak",
        },
    },
    {
        "timestamp": "2026-03-10T08:12:10.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.105",
        "dest_ip": "8.8.8.8",
        "proto": "UDP",
        "dns": {"type": "query", "rrname": "malicious.xyz"},
    },
    {
        "timestamp": "2026-03-10T08:12:20.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.105",
        "dest_ip": "8.8.8.8",
        "proto": "UDP",
        "dns": {"type": "query", "rrname": "evil.com"},
    },
    {
        "timestamp": "2026-03-10T08:12:30.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.105",
        "dest_ip": "8.8.8.8",
        "proto": "UDP",
        "dns": {"type": "query", "rrname": "phishing.net"},
    },
    {
        "timestamp": "2026-03-10T08:14:00.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.50",
        "dest_ip": "8.8.4.4",
        "proto": "UDP",
        "dns": {"type": "query", "rrname": "google.com"},
    },
]


class TestLoadLogs:
    """Тесты загрузки логов."""

    def test_load_valid_file(self, tmp_path):
        filepath = tmp_path / "test.json"
        filepath.write_text(json.dumps(SAMPLE_EVENTS), encoding="utf-8")

        result = load_logs(str(filepath))

        assert len(result) == 7

    def test_load_nonexistent_file(self, capsys):
        result = load_logs("/nonexistent/path.json")

        assert result == []

    def test_load_invalid_json(self, tmp_path, capsys):
        filepath = tmp_path / "bad.json"
        filepath.write_text("not valid json", encoding="utf-8")

        result = load_logs(str(filepath))

        assert result == []


class TestExtractAlerts:
    """Тесты извлечения алертов."""

    def test_extract_correct_count(self):
        df = extract_alerts(SAMPLE_EVENTS)

        assert len(df) == 3

    def test_extract_columns(self):
        df = extract_alerts(SAMPLE_EVENTS)

        assert "src_ip" in df.columns
        assert "severity" in df.columns
        assert "signature" in df.columns
        assert "category" in df.columns

    def test_extract_empty_events(self):
        df = extract_alerts([])

        assert len(df) == 0

    def test_extract_severity_values(self):
        df = extract_alerts(SAMPLE_EVENTS)

        assert set(df["severity"].tolist()) == {1, 3}


class TestExtractDnsQueries:
    """Тесты извлечения DNS-запросов."""

    def test_extract_correct_count(self):
        df = extract_dns_queries(SAMPLE_EVENTS)

        assert len(df) == 4

    def test_extract_domains(self):
        df = extract_dns_queries(SAMPLE_EVENTS)

        domains = df["domain"].tolist()
        assert "malicious.xyz" in domains
        assert "google.com" in domains

    def test_extract_empty(self):
        df = extract_dns_queries([])

        assert len(df) == 0


class TestFindSuspiciousIps:
    """Тесты поиска подозрительных IP."""

    def test_finds_top_ip(self):
        alerts_df = extract_alerts(SAMPLE_EVENTS)

        result = find_suspicious_ips(alerts_df, severity_threshold=2)

        assert len(result) >= 1
        assert result[0]["ip"] == "192.168.1.105"
        assert result[0]["alert_count"] == 2

    def test_empty_alerts(self):
        result = find_suspicious_ips(pd.DataFrame())

        assert result == []

    def test_threshold_filters_correctly(self):
        alerts_df = extract_alerts(SAMPLE_EVENTS)

        result = find_suspicious_ips(alerts_df, severity_threshold=1)

        ips = [r["ip"] for r in result]
        assert "192.168.1.105" in ips
        assert "10.10.10.55" not in ips


class TestFindSuspiciousDns:
    """Тесты поиска подозрительной DNS-активности."""

    def test_finds_suspicious_ip(self):
        dns_df = extract_dns_queries(SAMPLE_EVENTS)

        result = find_suspicious_dns(dns_df, threshold=3)

        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.105"
        assert result[0]["query_count"] == 3

    def test_threshold_excludes_normal(self):
        dns_df = extract_dns_queries(SAMPLE_EVENTS)

        result = find_suspicious_dns(dns_df, threshold=3)

        ips = [r["ip"] for r in result]
        assert "192.168.1.50" not in ips

    def test_empty_dns(self):
        result = find_suspicious_dns(pd.DataFrame())

        assert result == []

    def test_domains_list(self):
        dns_df = extract_dns_queries(SAMPLE_EVENTS)

        result = find_suspicious_dns(dns_df, threshold=3)

        assert "malicious.xyz" in result[0]["domains"]
