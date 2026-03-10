"""
Модуль для работы с Vulners API.

Выполняет поиск уязвимостей (CVE) с высоким CVSS-баллом
через Vulners API v3.
"""

import logging
import os
from pathlib import Path

import requests
from dotenv import load_dotenv
from requests.exceptions import RequestException

from constants import Messages, VulnersConfig

load_dotenv(Path(__file__).parent / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def get_api_key() -> str | None:
    """Получает API ключ Vulners из переменной окружения."""
    api_key = os.environ.get(VulnersConfig.API_KEY_ENV_VAR)
    if not api_key:
        logger.warning("API ключ не задан: %s", VulnersConfig.API_KEY_ENV_VAR)
        return None
    return api_key


def fetch_vulnerabilities(
    api_key: str,
    query: str = VulnersConfig.DEFAULT_QUERY,
    limit: int = VulnersConfig.DEFAULT_LIMIT,
) -> list[dict]:
    """
    Ищет уязвимости через Vulners API.

    Args:
        api_key: API ключ Vulners.
        query: Поисковый запрос (Lucene-синтаксис).
        limit: Максимальное количество результатов.

    Returns:
        Список найденных уязвимостей.
    """
    url = f"{VulnersConfig.BASE_URL}{VulnersConfig.SEARCH_ENDPOINT}"
    payload = {"query": query, "skip": 0, "size": limit, "apiKey": api_key}

    try:
        response = requests.post(url, json=payload, timeout=VulnersConfig.REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        if data.get("result") != "OK":
            logger.error("API вернул ошибку: %s", data.get("data", {}).get("error"))
            return []

        search_results = data.get("data", {}).get("search", [])
        vulnerabilities = []

        for item in search_results:
            source = item.get("_source", {})
            cvss_score = source.get("cvss", {}).get("score", 0)
            vuln = {
                "id": source.get("id", "N/A"),
                "title": source.get("title", "N/A"),
                "cvss_score": cvss_score,
                "description": source.get("description", "")[:200],
                "published": source.get("published", "N/A"),
                "type": source.get("type", "N/A"),
            }
            vulnerabilities.append(vuln)

        logger.info("Найдено %d уязвимостей", len(vulnerabilities))
        return vulnerabilities

    except RequestException as e:
        logger.exception("Ошибка запроса к Vulners API: %s", e)
        print(Messages.FETCH_ERROR.format(error=e))
        return []


def filter_critical(
    vulnerabilities: list[dict],
    threshold: float = VulnersConfig.CRITICAL_CVSS_THRESHOLD,
) -> list[dict]:
    """Фильтрует уязвимости по CVSS-баллу >= threshold."""
    critical = [v for v in vulnerabilities if v.get("cvss_score", 0) >= threshold]
    critical.sort(key=lambda v: v["cvss_score"], reverse=True)
    return critical
