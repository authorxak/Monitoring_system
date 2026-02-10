import re
from datetime import datetime, timedelta
from models import Host, Metric, Alert, AlertSeverity, AlertStatus
from extensions import db
from collections import defaultdict
import ipaddress


class AttackDetector:
    """Детектор атак на серверы"""

    def __init__(self):
        self.attack_patterns = {
            'ssh_bruteforce': {
                'name': 'SSH Brute Force Attack',
                'description': 'Множественные попытки подключения по SSH',
                'severity': AlertSeverity.CRITICAL,
                'threshold': 5,  # 5 попыток в минуту
                'window_minutes': 1
            },
            'port_scan': {
                'name': 'Port Scanning',
                'description': 'Сканирование портов на хосте',
                'severity': AlertSeverity.WARNING,
                'threshold': 10,  # 10 разных портов за минуту
                'window_minutes': 1
            },
            'dos_attack': {
                'name': 'DoS Attack',
                'description': 'Атака типа "Отказ в обслуживании"',
                'severity': AlertSeverity.CRITICAL,
                'threshold': 100,  # 100 запросов в секунду
                'window_minutes': 1
            },
            'sql_injection': {
                'name': 'SQL Injection Attempt',
                'description': 'Обнаружены признаки SQL-инъекции',
                'severity': AlertSeverity.CRITICAL,
                'threshold': 1,  # Любая попытка
                'window_minutes': 5
            },
            'xss_attack': {
                'name': 'XSS Attack Attempt',
                'description': 'Попытка межсайтового скриптирования',
                'severity': AlertSeverity.WARNING,
                'threshold': 1,  # Любая попытка
                'window_minutes': 5
            }
        }

        # Хранилище для отслеживания атак в реальном времени
        self.attack_logs = defaultdict(list)

    def detect_ssh_bruteforce(self, host_id, logs_data):
        """Обнаружение брутфорс атак по SSH"""
        attacks = []

        if not logs_data or 'ssh_logs' not in logs_data:
            return attacks

        ssh_logs = logs_data['ssh_logs']

        # Группируем неудачные попытки по IP за последнюю минуту
        failed_attempts = defaultdict(int)
        time_window = datetime.utcnow() - timedelta(minutes=1)

        for log in ssh_logs:
            if log.get('timestamp') and log.get('timestamp') > time_window:
                if 'Failed password' in log.get('message', '') or 'Invalid user' in log.get('message', ''):
                    src_ip = log.get('source_ip', 'unknown')
                    failed_attempts[src_ip] += 1

        # Создаем алерты для IP с превышением порога
        threshold = self.attack_patterns['ssh_bruteforce']['threshold']

        for ip, count in failed_attempts.items():
            if count >= threshold:
                attacks.append({
                    'host_id': host_id,
                    'title': f'SSH Brute Force from {ip}',
                    'description': f'{count} неудачных попыток входа по SSH с IP {ip} за последнюю минуту',
                    'severity': AlertSeverity.CRITICAL.value,
                    'alert_type': 'ssh_bruteforce',
                    'trigger_value': count,
                    'trigger_threshold': threshold,
                    'alert_data': {
                        'attacker_ip': ip,
                        'attempt_count': count,
                        'time_window': '1 minute',
                        'log_samples': [log for log in ssh_logs if log.get('source_ip') == ip][:3]
                    }
                })

        return attacks

    def detect_port_scan(self, host_id, logs_data):
        """Обнаружение сканирования портов"""
        attacks = []

        if not logs_data or 'connection_logs' not in logs_data:
            return attacks

        conn_logs = logs_data['connection_logs']

        # Группируем попытки подключения по IP за последнюю минуту
        port_attempts = defaultdict(set)
        time_window = datetime.utcnow() - timedelta(minutes=1)

        for log in conn_logs:
            if log.get('timestamp') and log.get('timestamp') > time_window:
                src_ip = log.get('source_ip', 'unknown')
                dst_port = log.get('destination_port')
                if dst_port:
                    port_attempts[src_ip].add(dst_port)

        # Создаем алерты для IP, сканирующих много портов
        threshold = self.attack_patterns['port_scan']['threshold']

        for ip, ports in port_attempts.items():
            if len(ports) >= threshold:
                attacks.append({
                    'host_id': host_id,
                    'title': f'Port Scan from {ip}',
                    'description': f'Сканирование {len(ports)} портов с IP {ip} за последнюю минуту',
                    'severity': AlertSeverity.WARNING.value,
                    'alert_type': 'port_scan',
                    'trigger_value': len(ports),
                    'trigger_threshold': threshold,
                    'alert_data': {
                        'attacker_ip': ip,
                        'ports_scanned': list(ports),
                        'time_window': '1 minute',
                        'is_sequential': self._is_sequential_ports(ports)
                    }
                })

        return attacks

    def detect_dos_attack(self, host_id, metrics_data):
        """Обнаружение DoS атак по метрикам нагрузки"""
        attacks = []

        if not metrics_data:
            return attacks

        # Проверяем метрики за последнюю минуту
        time_window = datetime.utcnow() - timedelta(minutes=1)

        # Ищем резкий рост запросов
        request_counts = []
        for metric in metrics_data:
            if metric.get('timestamp') and metric.get('timestamp') > time_window:
                if metric.get('metric_type') == 'requests_per_second':
                    request_counts.append(metric.get('value', 0))

        if request_counts:
            avg_requests = sum(request_counts) / len(request_counts)
            threshold = self.attack_patterns['dos_attack']['threshold']

            if avg_requests > threshold:
                # Проверяем, есть ли много запросов с одного IP
                src_ips = defaultdict(int)
                for metric in metrics_data:
                    if metric.get('extra_data', {}).get('source_ip'):
                        src_ips[metric['extra_data']['source_ip']] += 1

                top_attacker = max(src_ips.items(), key=lambda x: x[1]) if src_ips else ('unknown', 0)

                attacks.append({
                    'host_id': host_id,
                    'title': f'Possible DoS Attack',
                    'description': f'Высокая нагрузка: {avg_requests:.1f} запросов/сек (порог: {threshold})',
                    'severity': AlertSeverity.CRITICAL.value,
                    'alert_type': 'dos_attack',
                    'trigger_value': avg_requests,
                    'trigger_threshold': threshold,
                    'alert_data': {
                        'avg_requests_per_second': avg_requests,
                        'peak_requests': max(request_counts) if request_counts else 0,
                        'top_source_ip': top_attacker[0],
                        'requests_from_top_ip': top_attacker[1],
                        'unique_ips': len(src_ips)
                    }
                })

        return attacks

    def detect_sql_injection(self, host_id, logs_data):
        """Обнаружение попыток SQL инъекций"""
        attacks = []

        if not logs_data or 'web_logs' not in logs_data:
            return attacks

        web_logs = logs_data['web_logs']
        sql_patterns = [
            r"('.+--|--|;--|;|\/\*|\*\/|@@|char\(|nchar\(|varchar\(|xp_|exec\s|sp_|union\s+select|insert\s+into|select.+from|drop\s+table|delete\s+from|truncate\s+table)",
            r"(union.*select|select.*from.*insert|or\s+['\d\s]+=['\d\s]+)",
            r"(1=1|' OR '1'='1|' OR 'a'='a)",
            r"(waitfor delay|sleep\(|benchmark\()"
        ]

        time_window = datetime.utcnow() - timedelta(minutes=5)

        for log in web_logs:
            if log.get('timestamp') and log.get('timestamp') > time_window:
                url = log.get('url', '')
                user_agent = log.get('user_agent', '')
                src_ip = log.get('source_ip', 'unknown')

                # Проверяем URL на SQL инъекции
                for pattern in sql_patterns:
                    if re.search(pattern, url, re.IGNORECASE) or re.search(pattern, user_agent, re.IGNORECASE):
                        attacks.append({
                            'host_id': host_id,
                            'title': f'SQL Injection Attempt from {src_ip}',
                            'description': f'Обнаружена попытка SQL инъекции в URL',
                            'severity': AlertSeverity.CRITICAL.value,
                            'alert_type': 'sql_injection',
                            'trigger_value': 1,
                            'trigger_threshold': 1,
                            'alert_data': {
                                'attacker_ip': src_ip,
                                'url': url[:200],  # Ограничиваем длину
                                'user_agent': user_agent[:100],
                                'pattern_matched': pattern,
                                'timestamp': log.get('timestamp').isoformat() if log.get('timestamp') else None
                            }
                        })
                        break  # Не создаем дубликаты для одного лога

        return attacks

    def detect_xss_attack(self, host_id, logs_data):
        """Обнаружение попыток XSS атак"""
        attacks = []

        if not logs_data or 'web_logs' not in logs_data:
            return attacks

        web_logs = logs_data['web_logs']
        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror=|onload=|onclick=|onmouseover=",
            r"alert\(|confirm\(|prompt\(",
            r"<iframe|<embed|<object",
            r"eval\("
        ]

        time_window = datetime.utcnow() - timedelta(minutes=5)

        for log in web_logs:
            if log.get('timestamp') and log.get('timestamp') > time_window:
                url = log.get('url', '')
                params = log.get('parameters', {})
                src_ip = log.get('source_ip', 'unknown')

                # Проверяем все части запроса
                search_text = url + ' ' + str(params)

                for pattern in xss_patterns:
                    if re.search(pattern, search_text, re.IGNORECASE):
                        attacks.append({
                            'host_id': host_id,
                            'title': f'XSS Attack Attempt from {src_ip}',
                            'description': f'Обнаружена попытка межсайтового скриптинга',
                            'severity': AlertSeverity.WARNING.value,
                            'alert_type': 'xss_attack',
                            'trigger_value': 1,
                            'trigger_threshold': 1,
                            'alert_data': {
                                'attacker_ip': src_ip,
                                'url': url[:200],
                                'matched_pattern': pattern,
                                'parameters': params,
                                'timestamp': log.get('timestamp').isoformat() if log.get('timestamp') else None
                            }
                        })
                        break

        return attacks

    def _is_sequential_ports(self, ports):
        """Проверяет, являются ли порты последовательными (признак сканирования)"""
        if len(ports) < 3:
            return False

        sorted_ports = sorted(ports)
        sequential_count = 0
        max_sequential = 0

        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] == sorted_ports[i - 1] + 1:
                sequential_count += 1
                max_sequential = max(max_sequential, sequential_count)
            else:
                sequential_count = 0

        return max_sequential >= 3  # 3+ последовательных порта

    def process_logs_for_attacks(self, host_id, logs_data):
        """Обработка логов для обнаружения всех типов атак"""
        all_attacks = []

        # Проверяем все типы атак
        all_attacks.extend(self.detect_ssh_bruteforce(host_id, logs_data))
        all_attacks.extend(self.detect_port_scan(host_id, logs_data))
        all_attacks.extend(self.detect_dos_attack(host_id, logs_data.get('metrics', [])))
        all_attacks.extend(self.detect_sql_injection(host_id, logs_data))
        all_attacks.extend(self.detect_xss_attack(host_id, logs_data))

        # Сохраняем лог атак для статистики
        for attack in all_attacks:
            self._log_attack(host_id, attack['alert_type'], attack['alert_data'])

        return all_attacks

    def _log_attack(self, host_id, attack_type, attack_data):
        """Логирование атаки для последующего анализа"""
        log_entry = {
            'timestamp': datetime.utcnow(),
            'host_id': host_id,
            'attack_type': attack_type,
            'data': attack_data
        }
        self.attack_logs[host_id].append(log_entry)

        # Ограничиваем историю последними 1000 записей на хост
        if len(self.attack_logs[host_id]) > 1000:
            self.attack_logs[host_id] = self.attack_logs[host_id][-1000:]

    def get_attack_stats(self, host_id=None):
        """Получение статистики по атакам"""
        stats = {
            'total_attacks': 0,
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'recent_attacks': []
        }

        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)

        for h_id, logs in self.attack_logs.items():
            if host_id and h_id != host_id:
                continue

            for log in logs:
                stats['total_attacks'] += 1
                stats['by_type'][log['attack_type']] += 1

                # Определяем severity по типу атаки
                attack_info = self.attack_patterns.get(log['attack_type'], {})
                severity = attack_info.get('severity', AlertSeverity.WARNING).value
                stats['by_severity'][severity] += 1

                # Недавние атаки (последний час)
                if log['timestamp'] > hour_ago:
                    stats['recent_attacks'].append({
                        'host_id': h_id,
                        'type': log['attack_type'],
                        'timestamp': log['timestamp'].isoformat(),
                        'data': log['data']
                    })

        # Сортируем недавние атаки по времени
        stats['recent_attacks'].sort(key=lambda x: x['timestamp'], reverse=True)

        return stats


# Глобальный экземпляр детектора
attack_detector = AttackDetector()