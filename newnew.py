import psutil
import requests
import time
import subprocess
import json
import socket
import platform
import os
import sys
from datetime import datetime
import netifaces


class MonitoringAgent:
    def __init__(self, server_url):
        self.server_url = server_url.rstrip('/')
        self.host_id = None

        # Автоматически определяем информацию о системе
        self.host_info = self.collect_host_info()

        print(f"🚀 Agent initialized:")
        print(f"   Name: {self.host_info['name']}")
        print(f"   IP: {self.host_info['ip_address']}")
        print(f"   OS: {self.host_info['os']}")
        print(f"   Server: {self.server_url}")

    def collect_host_info(self):
        """Сбор информации о хосте"""
        info = {}

        # 1. Имя хоста
        info['name'] = socket.gethostname()

        # 2. IP адреса
        info['ip_address'] = self.get_main_ip()
        info['all_ips'] = self.get_all_ips()

        # 3. Операционная система
        info['os'] = platform.system()
        info['os_version'] = platform.release()
        info['os_details'] = platform.platform()

        # 4. Процессор
        info['cpu_count'] = psutil.cpu_count()
        info['cpu_model'] = self.get_cpu_model()

        # 5. Память
        mem = psutil.virtual_memory()
        info['memory_total_gb'] = round(mem.total / (1024 ** 3), 2)

        # 6. Диски
        info['disks'] = self.get_disk_info()

        # 7. Сеть
        info['network_interfaces'] = self.get_network_info()

        return info

    def get_main_ip(self):
        """Получение основного IP адреса"""
        try:
            # Пробуем подключиться к внешнему сервису для определения внешнего IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            # Fallback: получаем первый не-localhost IP
            hostname = socket.gethostname()
            try:
                return socket.gethostbyname(hostname)
            except:
                return "127.0.0.1"

    def get_all_ips(self):
        """Получение всех IP адресов"""
        ips = []
        try:
            for interface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(interface):
                    for addr_info in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        if ip != '127.0.0.1':
                            ips.append({
                                'interface': interface,
                                'ip': ip,
                                'netmask': addr_info.get('netmask', ''),
                                'broadcast': addr_info.get('broadcast', '')
                            })
        except:
            pass
        return ips

    def get_cpu_model(self):
        """Получение модели процессора"""
        try:
            if platform.system() == "Linux":
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.startswith('model name'):
                            return line.split(':')[1].strip()
            elif platform.system() == "Windows":
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                return winreg.QueryValueEx(key, "ProcessorNameString")[0]
        except:
            pass
        return "Unknown"

    def get_disk_info(self):
        """Информация о дисках"""
        disks = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total_gb': round(usage.total / (1024 ** 3), 2),
                    'used_gb': round(usage.used / (1024 ** 3), 2),
                    'free_gb': round(usage.free / (1024 ** 3), 2),
                    'percent': usage.percent
                })
            except:
                continue
        return disks

    def get_network_info(self):
        """Информация о сетевых интерфейсах"""
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            interface_info = {'name': name, 'addresses': []}
            for addr in addrs:
                interface_info['addresses'].append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask if hasattr(addr, 'netmask') else None,
                    'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                })
            interfaces.append(interface_info)
        return interfaces

    def register_host(self):
        """Регистрация хоста на сервере мониторинга"""
        registration_data = {
            "name": self.host_info['name'],
            "ip_address": self.host_info['ip_address'],
            "hostname": self.host_info['name'],
            "os": f"{self.host_info['os']} {self.host_info['os_version']}",
            "extra_info": {
                "cpu_model": self.host_info['cpu_model'],
                "cpu_count": self.host_info['cpu_count'],
                "memory_gb": self.host_info['memory_total_gb'],
                "os_details": self.host_info['os_details']
            }
        }

        try:
            print(f"📝 Registering host at {self.server_url}/api/v1/register...")
            response = requests.post(
                f"{self.server_url}/api/v1/register",
                json=registration_data,
                timeout=10
            )

            if response.status_code in [200, 201]:
                data = response.json()
                self.host_id = data['host']['id']
                print(f"✅ Host registered successfully! ID: {self.host_id}")
                return True
            else:
                print(f"❌ Registration failed: {response.status_code}")
                print(f"Response: {response.text}")
        except Exception as e:
            print(f"❌ Registration error: {e}")

        return False

    def collect_metrics(self):
        """Сбор текущих метрик"""
        metrics = []

        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        metrics.append({
            'type': 'cpu',
            'value': cpu_percent,
            'unit': '%',
            'extra': {
                'per_cpu': psutil.cpu_percent(interval=0.1, percpu=True),
                'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
            }
        })

        # Memory
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        metrics.append({
            'type': 'memory',
            'value': mem.percent,
            'unit': '%',
            'extra': {
                'used_gb': round(mem.used / (1024 ** 3), 2),
                'available_gb': round(mem.available / (1024 ** 3), 2),
                'swap_percent': swap.percent
            }
        })

        # Disk
        for disk in self.host_info['disks']:
            metrics.append({
                'type': f'disk_{disk["mountpoint"].replace("/", "_")}',
                'value': disk['percent'],
                'unit': '%',
                'extra': {
                    'mountpoint': disk['mountpoint'],
                    'free_gb': disk['free_gb'],
                    'used_gb': disk['used_gb']
                }
            })

        # Network
        net_io = psutil.net_io_counters()
        metrics.append({
            'type': 'network_bytes',
            'value': net_io.bytes_sent + net_io.bytes_recv,
            'unit': 'bytes',
            'extra': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        })

        # Processes
        metrics.append({
            'type': 'processes',
            'value': len(psutil.pids()),
            'unit': 'count'
        })

        # Uptime
        metrics.append({
            'type': 'uptime',
            'value': time.time() - psutil.boot_time(),
            'unit': 'seconds'
        })

        # Температура (если доступно)
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    if entries:
                        metrics.append({
                            'type': f'temp_{name}',
                            'value': entries[0].current,
                            'unit': '°C'
                        })
        except:
            pass

        return metrics

    def collect_security_logs(self):
        """Сбор логов безопасности для обнаружения атак"""
        logs = {
            'ssh_logs': [],
            'connection_logs': [],
            'auth_logs': []
        }

        # 1. SSH логи (для обнаружения брутфорса)
        logs['ssh_logs'] = self.collect_ssh_logs()

        # 2. Активные соединения (для обнаружения сканирования портов)
        logs['connection_logs'] = self.get_active_connections()

        # 3. Логи аутентификации
        logs['auth_logs'] = self.get_auth_logs()

        return logs

    def collect_ssh_logs(self):
        """Сбор SSH логов"""
        ssh_logs = []

        try:
            # Пути к логам SSH
            log_paths = [
                '/var/log/auth.log',
                '/var/log/secure',
                '/var/log/messages'
            ]

            for log_path in log_paths:
                if os.path.exists(log_path):
                    # Читаем последние 50 строк
                    result = subprocess.run(
                        ['tail', '-50', log_path],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    for line in result.stdout.strip().split('\n'):
                        if line and ('sshd' in line.lower() or 'ssh' in line.lower()):
                            # Ищем IP в логе
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            source_ip = ip_match.group(1) if ip_match else 'unknown'

                            ssh_logs.append({
                                'timestamp': datetime.utcnow().isoformat(),
                                'source_ip': source_ip,
                                'message': line[:300]  # Ограничиваем длину
                            })
                    break  # Используем первый найденный файл

        except Exception as e:
            print(f"⚠️ Error reading SSH logs: {e}")

        return ssh_logs

    def get_active_connections(self):
        """Получить активные соединения"""
        connections = []

        try:
            # Используем ss для получения соединений
            result = subprocess.run(
                ['ss', '-tun'],
                capture_output=True,
                text=True,
                timeout=5
            )

            lines = result.stdout.strip().split('\n')[1:]  # Пропускаем заголовок

            for line in lines:
                if line:
                    parts = line.split()
                    if len(parts) >= 5:
                        remote_addr = parts[4]
                        if ':' in remote_addr:
                            remote_ip = remote_addr.split(':')[0]
                            remote_port = remote_addr.split(':')[1]

                            connections.append({
                                'timestamp': datetime.utcnow().isoformat(),
                                'source_ip': remote_ip,
                                'destination_port': int(remote_port),
                                'protocol': 'TCP'
                            })

        except Exception as e:
            print(f"⚠️ Error getting connections: {e}")

        return connections

    def get_auth_logs(self):
        """Получить логи аутентификации"""
        logs = []

        try:
            # Проверяем последние неудачные попытки входа
            result = subprocess.run(
                ['lastb', '-n', '20'],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.strip().split('\n'):
                if line and 'ssh' not in line:  # Исключаем SSH строки
                    parts = line.split()
                    if len(parts) >= 3:
                        logs.append({
                            'timestamp': datetime.utcnow().isoformat(),
                            'user': parts[0],
                            'source': parts[2],
                            'type': 'failed_login'
                        })

        except Exception as e:
            print(f"⚠️ Error getting auth logs: {e}")

        return logs

    def collect_security_logs(self):
        """Сбор логов безопасности"""
        logs = {
            'ssh_logs': [],
            'connection_logs': [],
            'auth_logs': [],
            'system_logs': []
        }

        # SSH logs для Linux
        if platform.system() == "Linux":
            ssh_logs = self.get_ssh_logs()
            if ssh_logs:
                logs['ssh_logs'] = ssh_logs

        # Активные соединения
        logs['connection_logs'] = self.get_active_connections()

        # Auth logs
        logs['auth_logs'] = self.get_auth_logs()

        return logs

    def get_ssh_logs(self):
        """Получение SSH логов"""
        logs = []
        log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/messages'
        ]

        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    # Последние 50 строк
                    result = subprocess.run(
                        ['tail', '-50', log_file],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    for line in result.stdout.strip().split('\n'):
                        if 'sshd' in line.lower() or 'ssh' in line.lower():
                            logs.append({
                                'timestamp': datetime.utcnow().isoformat(),
                                'log_file': log_file,
                                'message': line[:500]
                            })
                except:
                    continue
                break

        return logs

    def get_active_connections(self):
        """Получение активных соединений"""
        connections = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    connections.append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'local_ip': conn.laddr.ip if conn.laddr else '',
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_ip': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status,
                        'pid': conn.pid
                    })
        except:
            pass

        return connections

    def get_auth_logs(self):
        """Получение логов аутентификации"""
        logs = []

        # Проверяем последние неудачные попытки входа
        try:
            if platform.system() == "Linux":
                # Последние 10 неудачных попыток входа
                result = subprocess.run(
                    ['lastb', '-n', '10'],
                    capture_output=True,
                    text=True
                )

                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 3:
                            logs.append({
                                'type': 'failed_login',
                                'user': parts[0],
                                'source': parts[2] if len(parts) > 2 else 'unknown',
                                'timestamp': datetime.utcnow().isoformat()
                            })
        except:
            pass

        return logs

    def send_data(self):
        """Отправка всех данных на сервер"""
        if not self.host_id:
            if not self.register_host():
                print("⚠️ Cannot send data: host registration failed")
                return

        try:
            # 1. Собираем и отправляем метрики (как раньше)
            metrics = self.collect_metrics()
            metrics_response = requests.post(
                f"{self.server_url}/api/v1/metrics",
                json={'host_id': self.host_id, 'metrics': metrics},
                timeout=10
            )

            # 2. Собираем и отправляем логи безопасности (НОВОЕ!)
            logs = self.collect_security_logs()

            # Проверяем, есть ли логи для отправки
            if any(logs.values()):  # Если есть хоть что-то в логах
                logs_response = requests.post(
                    f"{self.server_url}/api/v1/logs",
                    json={'host_id': self.host_id, 'logs': logs},
                    timeout=15
                )

                if logs_response.status_code == 200:
                    result = logs_response.json()
                    attacks = result.get('attacks_detected', 0)
                    if attacks > 0:
                        print(f"🚨 {attacks} attacks detected!")
                else:
                    print(f"⚠️ Logs send failed: {logs_response.status_code}")

            print(f"✅ Data sent at {datetime.now().strftime('%H:%M:%S')}")
            print(f"   Metrics: {metrics_response.status_code}, Logs: {len(logs['ssh_logs'])} SSH entries")

        except Exception as e:
            print(f"❌ Error sending data: {e}")

# Конфигурация и запуск
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Monitoring Agent')
    parser.add_argument('--server', required=True, help='Monitoring server URL (e.g., http://192.168.1.99:5000)')
    parser.add_argument('--interval', type=int, default=60, help='Interval in seconds (default: 60)')

    args = parser.parse_args()

    agent = MonitoringAgent(server_url=args.server)
    agent.run(interval_seconds=args.interval)
