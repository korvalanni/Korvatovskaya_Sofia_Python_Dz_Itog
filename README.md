# Автоматизированный мониторинг и реагирование на угрозы

Итоговое домашнее задание по дисциплине «Программирование на Python».

**Автор:** Корватовская София

## Описание

Инструмент на Python для автоматизированного мониторинга угроз информационной безопасности:

1. **Сбор данных** из двух источников:
   - **Vulners API** — поиск CVE-уязвимостей с высоким CVSS-баллом
   - **Логи Suricata** — анализ сетевых алертов и DNS-запросов

2. **Анализ данных**:
   - Выявление подозрительных IP-адресов (по количеству высокоприоритетных алертов)
   - Обнаружение аномальной DNS-активности (частые запросы к подозрительным доменам)
   - Фильтрация критических уязвимостей по CVSS >= 7.0

3. **Реагирование на угрозы**:
   - Имитация блокировки подозрительных IP-адресов
   - Отправка уведомлений при обнаружении критических уязвимостей

4. **Отчётность и визуализация**:
   - Сохранение отчёта в JSON и CSV
   - Построение графиков: топ подозрительных IP + распределение CVSS-баллов

## Структура проекта

```
├── .github/workflows/tests.yml   # CI/CD пайплайн (lint + unit + integration)
├── logs/suricata_sample.json      # Пример логов Suricata
├── tests/                         # Тесты (pytest)
│   ├── test_log_analyzer.py       # Тесты анализа логов
│   ├── test_vulners_client.py     # Тесты клиента Vulners API
│   ├── test_threat_monitor.py     # Тесты главного модуля
│   └── test_integration.py        # Интеграционные тесты (реальный API)
├── constants.py                   # Константы и сообщения
├── log_analyzer.py                # Анализ логов Suricata
├── vulners_client.py              # Клиент Vulners API
├── threat_monitor.py              # Главный скрипт
├── requirements.txt               # Зависимости
├── pyproject.toml                 # Конфигурация проекта
└── README.md
```

## Установка и запуск

```bash
# Создание виртуального окружения
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Установка зависимостей
pip install -r requirements.txt

# Настройка API-ключа (опционально)
# Создайте файл .env и укажите ключ:
echo "VULNERS_API_KEY=ваш_ключ" > .env

# Запуск
python threat_monitor.py
```

## Тестирование

```bash
# Unit-тесты
pytest --ignore=tests/test_integration.py

# Все тесты (с API-ключом)
pytest

# С покрытием
pytest --cov=. --ignore=tests/test_integration.py
```

## CI/CD

GitHub Actions автоматически запускает при push/PR:
1. **Lint** — проверка кода через ruff
2. **Unit tests** — тесты на Python 3.10 и 3.12
3. **Integration tests** — тесты с реальным API (только push в main)
