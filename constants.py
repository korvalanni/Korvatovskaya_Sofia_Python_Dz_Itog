"""Общие константы приложения."""


class VulnersConfig:
    """Конфигурация Vulners API."""

    API_KEY_ENV_VAR = "VULNERS_API_KEY"
    BASE_URL = "https://vulners.com/api/v3"
    SEARCH_ENDPOINT = "/search/lucene/"
    REQUEST_TIMEOUT = 15
    CRITICAL_CVSS_THRESHOLD = 7.0
    DEFAULT_QUERY = "type:cve AND cvss.score:[7 TO 10]"
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

    MISSING_API_KEY = "[!] API ключ не задан в переменной {env_var}"
    API_KEY_HINT = "    Получить ключ: https://vulners.com -> Личный кабинет -> API Key"
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
