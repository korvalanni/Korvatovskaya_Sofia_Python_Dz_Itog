"""Общие константы приложения."""


class NvdConfig:
    """Конфигурация NVD NIST API (National Vulnerability Database)."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_TIMEOUT = 30
    CRITICAL_CVSS_THRESHOLD = 7.0
    DEFAULT_SEVERITY = "CRITICAL"
    DEFAULT_LIMIT = 20


class LogConfig:
    """Конфигурация анализа логов."""

    DEFAULT_LOG_PATH = "logs/suricata_sample.json"
    SUSPICIOUS_DNS_THRESHOLD = 3
    HIGH_SEVERITY_THRESHOLD = 2


class ReportConfig:
    """Конфигурация отчётов."""

    JSON_REPORT = "reports/threat_report.json"
    CSV_REPORT = "reports/threat_report.csv"
    CHART_ALERTS = "reports/top_suspicious_ips.png"
    CHART_CVSS = "reports/cvss_distribution.png"


class Messages:
    """Сообщения для пользователя."""

    NVD_FETCH_ERROR = "[!] Ошибка при запросе к NVD API: {error}"
    FETCH_ERROR = "[!] Ошибка при запросе к API: {error}"
    LOG_LOAD_ERROR = "[!] Не удалось загрузить логи: {error}"
    THREAT_FOUND = "[ALERT] Обнаружена угроза: {description}"
    IP_BLOCKED = "[ACTION] IP {ip} добавлен в чёрный список (имитация блокировки)"
    NOTIFICATION_SENT = "[ACTION] Уведомление отправлено: {message}"
    REPORT_SAVED = "[OK] Отчёт сохранён: {path}"
    CHART_SAVED = "[OK] График сохранён: {path}"
    NO_THREATS = "[OK] Угроз не обнаружено"


class UI:
    """Константы для отображения UI."""

    SEPARATOR = "=" * 60
    THIN_SEP = "-" * 60
