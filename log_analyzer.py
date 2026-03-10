"""
Модуль анализа логов Suricata.

Загружает JSON-логи, извлекает алерты и DNS-запросы,
определяет подозрительные IP-адреса.
"""

import json
import logging
from collections import Counter

import pandas as pd

from constants import LogConfig, Messages

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def load_logs(filepath: str = LogConfig.DEFAULT_LOG_PATH) -> list[dict]:
    """
    Загружает логи Suricata из JSON-файла.

    Args:
        filepath: Путь к файлу логов.

    Returns:
        Список событий.
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        logger.info("Загружено %d событий из %s", len(data), filepath)
        return data
    except (OSError, json.JSONDecodeError) as e:
        logger.exception("Ошибка загрузки логов: %s", e)
        print(Messages.LOG_LOAD_ERROR.format(error=e))
        return []


def extract_alerts(events: list[dict]) -> pd.DataFrame:
    """Извлекает события типа 'alert' в DataFrame."""
    alerts = []
    for event in events:
        if event.get("event_type") == "alert":
            alert_info = event.get("alert", {})
            alerts.append(
                {
                    "timestamp": event.get("timestamp"),
                    "src_ip": event.get("src_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "proto": event.get("proto"),
                    "signature": alert_info.get("signature", ""),
                    "severity": alert_info.get("severity", 0),
                    "category": alert_info.get("category", ""),
                }
            )
    df = pd.DataFrame(alerts)
    logger.info("Извлечено %d алертов", len(df))
    return df


def extract_dns_queries(events: list[dict]) -> pd.DataFrame:
    """Извлекает DNS-запросы в DataFrame."""
    queries = []
    for event in events:
        if event.get("event_type") == "dns":
            dns_info = event.get("dns", {})
            queries.append(
                {
                    "timestamp": event.get("timestamp"),
                    "src_ip": event.get("src_ip"),
                    "domain": dns_info.get("rrname", ""),
                }
            )
    df = pd.DataFrame(queries)
    logger.info("Извлечено %d DNS-запросов", len(df))
    return df


def find_suspicious_ips(
    alerts_df: pd.DataFrame,
    severity_threshold: int = LogConfig.HIGH_SEVERITY_THRESHOLD,
) -> list[dict]:
    """
    Находит подозрительные IP по количеству высокоприоритетных алертов.

    Args:
        alerts_df: DataFrame с алертами.
        severity_threshold: Порог severity (<=).

    Returns:
        Список словарей с IP и количеством алертов.
    """
    if alerts_df.empty:
        return []

    high_sev = alerts_df[alerts_df["severity"] <= severity_threshold]
    ip_counts = Counter(high_sev["src_ip"])
    result = [{"ip": ip, "alert_count": count} for ip, count in ip_counts.most_common()]
    return result


def find_suspicious_dns(
    dns_df: pd.DataFrame,
    threshold: int = LogConfig.SUSPICIOUS_DNS_THRESHOLD,
) -> list[dict]:
    """
    Находит IP с подозрительно большим числом DNS-запросов.

    Args:
        dns_df: DataFrame с DNS-запросами.
        threshold: Порог количества запросов.

    Returns:
        Список словарей с IP, количеством запросов и доменами.
    """
    if dns_df.empty:
        return []

    ip_counts = (
        dns_df.groupby("src_ip")
        .agg(
            query_count=("domain", "count"),
            domains=("domain", lambda x: list(set(x))),
        )
        .reset_index()
    )

    suspicious = ip_counts[ip_counts["query_count"] >= threshold]
    result = []
    for _, row in suspicious.iterrows():
        result.append(
            {
                "ip": row["src_ip"],
                "query_count": int(row["query_count"]),
                "domains": row["domains"],
            }
        )
    return result
