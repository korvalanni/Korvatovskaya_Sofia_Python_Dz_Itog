"""
Главный модуль: автоматизированный мониторинг и реагирование на угрозы.

Объединяет данные из двух источников (NVD NIST API + логи Suricata),
выявляет угрозы, имитирует реагирование и формирует отчёты с графиками.

Описание работы скрипта:
1. Загружает логи Suricata (JSON) — извлекает алерты и DNS-запросы.
2. Запрашивает уязвимости с высоким CVSS через NVD NIST API.
3. Анализирует данные: находит подозрительные IP и критические CVE.
4. Реагирует на угрозы: имитирует блокировку IP и отправку уведомлений.
5. Сохраняет отчёт в JSON и CSV.
6. Строит графики: топ подозрительных IP и распределение CVSS-баллов.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from constants import UI, LogConfig, Messages, ReportConfig  # noqa: E402
from log_analyzer import (  # noqa: E402
    extract_alerts,
    extract_dns_queries,
    find_suspicious_dns,
    find_suspicious_ips,
    load_logs,
)
from vulners_client import fetch_vulnerabilities, filter_critical  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def respond_to_threats(
    suspicious_ips: list[dict],
    suspicious_dns: list[dict],
    critical_vulns: list[dict],
) -> list[dict]:
    """
    Имитирует реагирование на обнаруженные угрозы.

    Для каждого подозрительного IP имитирует блокировку.
    Для каждой критической уязвимости выводит уведомление.

    Returns:
        Список действий реагирования.
    """
    actions = []

    blocked_ips = set()
    for entry in suspicious_ips:
        ip = entry["ip"]
        if ip not in blocked_ips:
            print(Messages.IP_BLOCKED.format(ip=ip))
            actions.append(
                {
                    "action": "block_ip",
                    "ip": ip,
                    "reason": f"Высокоприоритетные алерты: {entry['alert_count']}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            blocked_ips.add(ip)

    for entry in suspicious_dns:
        ip = entry["ip"]
        if ip not in blocked_ips:
            msg = f"Подозрительная DNS-активность с {ip}: {entry['query_count']} запросов"
            print(Messages.NOTIFICATION_SENT.format(message=msg))
            actions.append(
                {
                    "action": "notify",
                    "ip": ip,
                    "reason": msg,
                    "domains": entry["domains"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

    for vuln in critical_vulns[:5]:
        msg = f"Критическая уязвимость {vuln['id']} (CVSS {vuln['cvss_score']})"
        print(Messages.THREAT_FOUND.format(description=msg))
        actions.append(
            {
                "action": "alert_vulnerability",
                "cve_id": vuln["id"],
                "cvss_score": vuln["cvss_score"],
                "title": vuln["title"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    if not actions:
        print(Messages.NO_THREATS)

    return actions


def build_report(
    alerts_df: pd.DataFrame,
    suspicious_ips: list[dict],
    suspicious_dns: list[dict],
    critical_vulns: list[dict],
    actions: list[dict],
) -> dict:
    """Формирует итоговый отчёт."""
    alert_categories = {}
    if not alerts_df.empty:
        alert_categories = alerts_df["category"].value_counts().to_dict()

    return {
        "report_date": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_alerts": len(alerts_df),
            "unique_source_ips": int(alerts_df["src_ip"].nunique()) if not alerts_df.empty else 0,
            "suspicious_ips_count": len(suspicious_ips),
            "suspicious_dns_count": len(suspicious_dns),
            "critical_vulnerabilities": len(critical_vulns),
            "response_actions_taken": len(actions),
        },
        "alert_categories": alert_categories,
        "suspicious_ips": suspicious_ips,
        "suspicious_dns": suspicious_dns,
        "top_vulnerabilities": critical_vulns[:10],
        "response_actions": actions,
    }


def save_report_json(report: dict, filepath: str) -> bool:
    """Сохраняет отчёт в JSON."""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(Messages.REPORT_SAVED.format(path=filepath))
        return True
    except OSError as e:
        logger.exception("Ошибка сохранения JSON-отчёта: %s", e)
        return False


def save_report_csv(report: dict, filepath: str) -> bool:
    """Сохраняет основные данные отчёта в CSV."""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        rows = []

        for ip_info in report.get("suspicious_ips", []):
            rows.append(
                {
                    "type": "suspicious_ip",
                    "identifier": ip_info["ip"],
                    "detail": f"alerts: {ip_info['alert_count']}",
                    "severity": "high",
                }
            )

        for dns_info in report.get("suspicious_dns", []):
            rows.append(
                {
                    "type": "suspicious_dns",
                    "identifier": dns_info["ip"],
                    "detail": f"queries: {dns_info['query_count']}",
                    "severity": "medium",
                }
            )

        for vuln in report.get("top_vulnerabilities", []):
            rows.append(
                {
                    "type": "vulnerability",
                    "identifier": vuln["id"],
                    "detail": f"CVSS: {vuln['cvss_score']}",
                    "severity": "critical" if vuln["cvss_score"] >= 9 else "high",
                }
            )

        df = pd.DataFrame(rows)
        df.to_csv(filepath, index=False, encoding="utf-8")
        print(Messages.REPORT_SAVED.format(path=filepath))
        return True
    except OSError as e:
        logger.exception("Ошибка сохранения CSV-отчёта: %s", e)
        return False


def plot_suspicious_ips(suspicious_ips: list[dict], filepath: str) -> bool:
    """Строит столбчатый график топ подозрительных IP."""
    try:
        if not suspicious_ips:
            logger.warning("Нет данных для графика подозрительных IP")
            return False

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        top = suspicious_ips[:10]
        ips = [entry["ip"] for entry in top]
        counts = [entry["alert_count"] for entry in top]

        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.barh(ips, counts, color="#e74c3c", edgecolor="#c0392b")
        ax.set_xlabel("Количество алертов", fontsize=12)
        ax.set_ylabel("IP-адрес", fontsize=12)
        ax.set_title("Топ подозрительных IP-адресов по алертам", fontsize=14)
        ax.invert_yaxis()

        for bar, count in zip(bars, counts):
            ax.text(
                bar.get_width() + 0.1,
                bar.get_y() + bar.get_height() / 2,
                str(count),
                va="center",
                fontsize=10,
                fontweight="bold",
            )

        plt.tight_layout()
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(Messages.CHART_SAVED.format(path=filepath))
        return True
    except Exception as e:
        logger.exception("Ошибка при построении графика: %s", e)
        return False


def plot_cvss_distribution(vulnerabilities: list[dict], filepath: str) -> bool:
    """Строит гистограмму распределения CVSS-баллов."""
    try:
        if not vulnerabilities:
            logger.warning("Нет данных для графика CVSS")
            return False

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        scores = [v["cvss_score"] for v in vulnerabilities]

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.hist(
            scores,
            bins=[0, 2, 4, 6, 7, 8, 9, 10],
            color="#3498db",
            edgecolor="#2c3e50",
            alpha=0.85,
        )
        ax.set_xlabel("CVSS Score", fontsize=12)
        ax.set_ylabel("Количество уязвимостей", fontsize=12)
        ax.set_title("Распределение CVSS-баллов уязвимостей", fontsize=14)
        ax.axvline(
            x=7, color="#e74c3c", linestyle="--", linewidth=2, label="Порог критичности (7.0)"
        )
        ax.legend(fontsize=10)

        plt.tight_layout()
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(Messages.CHART_SAVED.format(path=filepath))
        return True
    except Exception as e:
        logger.exception("Ошибка при построении графика: %s", e)
        return False


def print_summary(report: dict) -> None:
    """Выводит краткую сводку в консоль."""
    summary = report["summary"]
    print()
    print(UI.SEPARATOR)
    print("  СВОДКА МОНИТОРИНГА УГРОЗ")
    print(UI.SEPARATOR)
    print(f"  Дата отчёта:               {report['report_date']}")
    print(f"  Всего алертов:             {summary['total_alerts']}")
    print(f"  Уникальных IP:             {summary['unique_source_ips']}")
    print(f"  Подозрительных IP:         {summary['suspicious_ips_count']}")
    print(f"  Подозрительных DNS:        {summary['suspicious_dns_count']}")
    print(f"  Критических уязвимостей:   {summary['critical_vulnerabilities']}")
    print(f"  Действий реагирования:     {summary['response_actions_taken']}")
    print(UI.SEPARATOR)

    if report.get("alert_categories"):
        print()
        print("  Категории алертов:")
        print(UI.THIN_SEP)
        for category, count in report["alert_categories"].items():
            print(f"    {category}: {count}")
    print()


def main() -> int:
    """
    Главная функция.

    Returns:
        0 при успехе, 1 при ошибке.
    """
    print(UI.SEPARATOR)
    print("  АВТОМАТИЗИРОВАННЫЙ МОНИТОРИНГ И РЕАГИРОВАНИЕ НА УГРОЗЫ")
    print(UI.SEPARATOR)
    print()

    # --- Источник 1: Логи Suricata ---
    print("[1/4] Загрузка и анализ логов Suricata...")
    events = load_logs(LogConfig.DEFAULT_LOG_PATH)
    if not events:
        print("[!] Логи пусты или не найдены, работаем только с API")

    alerts_df = extract_alerts(events)
    dns_df = extract_dns_queries(events)
    suspicious_ips = find_suspicious_ips(alerts_df)
    suspicious_dns = find_suspicious_dns(dns_df)

    # --- Источник 2: NVD NIST API ---
    print("[2/4] Запрос уязвимостей через NVD NIST API...")
    vulnerabilities = fetch_vulnerabilities()

    critical_vulns = filter_critical(vulnerabilities)

    # --- Реагирование ---
    print()
    print("[3/4] Реагирование на обнаруженные угрозы...")
    print(UI.THIN_SEP)
    actions = respond_to_threats(suspicious_ips, suspicious_dns, critical_vulns)

    # --- Отчёт и визуализация ---
    print()
    print("[4/4] Формирование отчётов и графиков...")
    report = build_report(alerts_df, suspicious_ips, suspicious_dns, critical_vulns, actions)

    save_report_json(report, ReportConfig.JSON_REPORT)
    save_report_csv(report, ReportConfig.CSV_REPORT)
    plot_suspicious_ips(suspicious_ips, ReportConfig.CHART_ALERTS)
    plot_cvss_distribution(vulnerabilities, ReportConfig.CHART_CVSS)

    print_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
