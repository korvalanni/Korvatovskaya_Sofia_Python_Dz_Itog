"""
Модуль для работы с NVD NIST API (National Vulnerability Database).

Выполняет поиск уязвимостей (CVE) с высоким CVSS-баллом
через NVD API 2.0 (https://nvd.nist.gov/).
"""

import logging

import requests
from requests.exceptions import RequestException

from constants import Messages, NvdConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _extract_cvss_score(metrics: dict) -> float:
    """Извлекает CVSS-балл из метрик NVD."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            return metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
    return 0.0


def _extract_description(descriptions: list[dict]) -> str:
    """Извлекает английское описание CVE."""
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")[:200]
    return descriptions[0].get("value", "")[:200] if descriptions else ""


def fetch_vulnerabilities(
    severity: str = NvdConfig.DEFAULT_SEVERITY,
    limit: int = NvdConfig.DEFAULT_LIMIT,
) -> list[dict]:
    """
    Ищет уязвимости через NVD NIST API 2.0.

    Args:
        severity: Уровень критичности (LOW, MEDIUM, HIGH, CRITICAL).
        limit: Максимальное количество результатов.

    Returns:
        Список найденных уязвимостей.
    """
    params = {
        "cvssV3Severity": severity,
        "resultsPerPage": limit,
    }

    try:
        response = requests.get(
            NvdConfig.BASE_URL, params=params, timeout=NvdConfig.REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        raw_vulns = data.get("vulnerabilities", [])
        vulnerabilities = []

        for item in raw_vulns:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_score = _extract_cvss_score(metrics)
            vuln = {
                "id": cve.get("id", "N/A"),
                "title": cve.get("id", "N/A"),
                "cvss_score": cvss_score,
                "description": _extract_description(cve.get("descriptions", [])),
                "published": cve.get("published", "N/A"),
                "type": "cve",
            }
            vulnerabilities.append(vuln)

        logger.info("Найдено %d уязвимостей через NVD API", len(vulnerabilities))
        return vulnerabilities

    except RequestException as e:
        logger.exception("Ошибка запроса к NVD API: %s", e)
        print(Messages.NVD_FETCH_ERROR.format(error=e))
        return []


def filter_critical(
    vulnerabilities: list[dict],
    threshold: float = NvdConfig.CRITICAL_CVSS_THRESHOLD,
) -> list[dict]:
    """Фильтрует уязвимости по CVSS-баллу >= threshold."""
    critical = [v for v in vulnerabilities if v.get("cvss_score", 0) >= threshold]
    critical.sort(key=lambda v: v["cvss_score"], reverse=True)
    return critical
