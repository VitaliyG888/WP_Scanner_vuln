#!/usr/bin/env python3
import os
import re
import sys
import json
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

# ------------------------------------------------------------------
# КОНФИГ
TARGET_PLUGINS_URL = "https://coastaldentalcare.com.au/wp-content/plugins/"
OUTPUT_REPORT = "vulnerable_functions_report.json"
THREADS = 20
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ОПАСНЫЕ ФУНКЦИИ ПО КАТЕГОРИЯМ
DANGEROUS_FUNCTIONS = {
    "system_exec": [
        "exec", "shell_exec", "system", "passthru", "popen", "proc_open",
        "pcntl_exec", "eval", "assert", "create_function", "call_user_func",
        "call_user_func_array", "register_tick_function", "register_shutdown_function"
    ],
    "file_operations": [
        "file_put_contents", "fwrite", "fopen", "file_get_contents",
        "file", "readfile", "include", "require", "include_once", "require_once",
        "unlink", "rmdir", "mkdir", "chmod", "chown", "copy", "rename", "move_uploaded_file"
    ],
    "database": [
        "mysqli_query", "mysql_query", "pg_query", "sqlite_query",
        "PDO::query", "wpdb::query", "wpdb::get_results"
    ],
    "deserialization": [
        "unserialize", "maybe_unserialize", "serialize",
        "json_decode", "json_encode"
    ],
    "http": [
        "curl_exec", "file_get_contents", "fopen", "get_headers",
        "wp_remote_get", "wp_remote_post", "wp_remote_request"
    ],
    "xss": [
        "print_r", "var_dump", "echo", "printf", "print"
    ]
}

# ВЕС РИСКА (чем выше, тем опаснее)
FUNCTION_RISK = {
    "system_exec": 10,
    "deserialization": 9,
    "file_operations": 8,
    "database": 7,
    "http": 6,
    "xss": 3
}

# ПАТТЕРНЫ ДЛЯ ПОИСКА ПОТЕНЦИАЛЬНЫХ SQLi
SQL_PATTERNS = [
    r"query\s*\(\s*['\"]\s*SELECT\s+.*?\$_(GET|POST|REQUEST|COOKIE)",
    r"\$wpdb->get_(results|row|var)\s*\(\s*['\"]\s*.*?\$_(GET|POST|REQUEST)",
    r"mysql_query\(\s*['\"]\s*SELECT\s+.*?\.\s*\$"
]

# ПОИСК ХАРДКОДНЫХ ПАРОЛЕЙ/КЛЮЧЕЙ
SECRET_PATTERNS = [
    r"(api_key|apikey|secret|password|passwd|auth_token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}",
    r"\$db_(user|pass|password|host|name)\s*=\s*['\"][^'\"]+",
    r"define\(\s*['\"](DB_PASSWORD|DB_USER|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY)",
]

# ------------------------------------------------------------------
def fetch_plugin_list(url):
    """Парсит индекс папки и возвращает список подпапок и ZIP-файлов"""
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            print(f"[!] Не удалось получить список плагинов: {resp.status_code}")
            return []
        # Простой парсинг ссылок (в идеале - BeautifulSoup)
        plugins = []
        for line in resp.text.split('\n'):
            href_match = re.search(r'href="([^"]+)"', line)
            if href_match:
                name = href_match.group(1)
                if name.startswith('?') or name.startswith('/') or name == 'Parent Directory':
                    continue
                # Это может быть папка или файл .zip
                if name.endswith('/') or name.endswith('.zip'):
                    plugins.append(name.rstrip('/'))
        return plugins
    except Exception as e:
        print(f"[!] Ошибка при получении списка: {e}")
        return []

def download_file(url, local_path):
    """Загружает файл или папку (рекурсивно)"""
    try:
        if url.endswith('/'):
            # Создаем папку
            os.makedirs(local_path, exist_ok=True)
            # Получаем содержимое папки
            resp = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                for line in resp.text.split('\n'):
                    href_match = re.search(r'href="([^"]+)"', line)
                    if href_match:
                        sub = href_match.group(1)
                        if sub.startswith('?') or sub.startswith('/') or sub == 'Parent Directory':
                            continue
                        sub_url = url + sub
                        sub_local = os.path.join(local_path, sub)
                        if sub.endswith('/'):
                            download_file(sub_url, sub_local)
                        else:
                            download_file(sub_url, sub_local)
            return
        else:
            # Скачиваем файл
            resp = requests.get(url, timeout=30, stream=True, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                with open(local_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                print(f"[+] Загружен: {local_path}")
            else:
                print(f"[!] Ошибка загрузки {url}: {resp.status_code}")
    except Exception as e:
        print(f"[!] Ошибка при загрузке {url}: {e}")

def scan_php_file(file_path):
    """Сканирует PHP-файл на опасные функции, возвращает отчёт"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return findings

    lines = content.split('\n')
    for i, line in enumerate(lines, start=1):
        line_lower = line.lower()
        # Проверяем опасные функции
        for category, funcs in DANGEROUS_FUNCTIONS.items():
            for func in funcs:
                # Ищем не просто функцию, а вызов с круглыми скобками
                pattern = r'\b' + re.escape(func) + r'\s*\('
                if re.search(pattern, line_lower):
                    findings.append({
                        "line": i,
                        "function": func,
                        "category": category,
                        "code": line.strip()[:200],
                        "risk": FUNCTION_RISK.get(category, 5),
                        "file": file_path
                    })

    # Поиск SQL-инъекций
    for pattern in SQL_PATTERNS:
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": i,
                    "function": "SQL_INJECTION_PATTERN",
                    "category": "database",
                    "code": line.strip()[:200],
                    "risk": 9,
                    "file": file_path
                })

    # Поиск секретов
    for pattern in SECRET_PATTERNS:
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": i,
                    "function": "SECRET_LEAK",
                    "category": "hardcoded_creds",
                    "code": line.strip()[:200],
                    "risk": 10,
                    "file": file_path
                })

    return findings

def scan_directory(root_dir):
    """Рекурсивно сканирует все .php файлы в папке"""
    all_findings = []
    php_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.endswith('.php'):
                php_files.append(os.path.join(dirpath, f))

    print(f"[*] Найдено PHP-файлов: {len(php_files)}")
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_php_file, f): f for f in php_files}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    all_findings.extend(res)
            except Exception as e:
                print(f"[!] Ошибка сканирования: {e}")

    return all_findings

def generate_report(findings, output_file):
    """Создаёт JSON и HTML-отчёт"""
    report = {
        "total_findings": len(findings),
        "by_risk": {},
        "by_category": {},
        "files_affected": set(),
        "findings": findings
    }

    for f in findings:
        risk = f.get("risk", 5)
        if risk >= 8:
            cat = "critical"
        elif risk >= 6:
            cat = "high"
        elif risk >= 4:
            cat = "medium"
        else:
            cat = "low"
        report["by_risk"][cat] = report["by_risk"].get(cat, 0) + 1
        report["by_category"][f.get("category", "other")] = report["by_category"].get(f.get("category", "other"), 0) + 1
        report["files_affected"].add(f.get("file", "unknown"))

    report["files_affected"] = list(report["files_affected"])
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    # Текстовый вывод
    print(f"\n[+] ОТЧЁТ ПО СКАНИРОВАНИЮ")
    print(f"Всего находок: {report['total_findings']}")
    print(f"Критических: {report['by_risk'].get('critical', 0)}")
    print(f"Высоких: {report['by_risk'].get('high', 0)}")
    print(f"Затронуто файлов: {len(report['files_affected'])}")
    print(f"Отчёт сохранён: {output_file}")

# ------------------------------------------------------------------
def main():
    print("[+] ЗАПУСК СКАНЕРА УЯЗВИМОСТЕЙ WP ПЛАГИНОВ")
    target_url = TARGET_PLUGINS_URL

    # 1. Получаем список плагинов
    plugins = fetch_plugin_list(target_url)
    print(f"[+] Найдено плагинов: {len(plugins)}")

    # 2. Скачиваем всё в local папку
    download_dir = "./downloaded_plugins"
    os.makedirs(download_dir, exist_ok=True)

    for plugin in plugins:
        if plugin.endswith('.zip'):
            # Скачиваем ZIP
            file_url = urljoin(target_url, plugin)
            local_path = os.path.join(download_dir, plugin)
            download_file(file_url, local_path)
        else:
            # Папка
            dir_url = urljoin(target_url, plugin + '/')
            local_dir = os.path.join(download_dir, plugin)
            download_file(dir_url, local_dir)

    # 3. Сканируем код
    print("[*] Начинаю рекурсивный анализ кода...")
    all_findings = scan_directory(download_dir)

    # 4. Генерируем отчёт
    generate_report(all_findings, OUTPUT_REPORT)

    print("[+] Сканирование завершено.")

if __name__ == "__main__":
    main()