#!/usr/bin/env python3
"""
Движок обнаружения атак и аномалий
"""
from datetime import datetime, timedelta
from models import db, Host, Metric, Alert, AlertStatus, AlertSeverity
import json
from typing import Dict, List, Optional


class SecurityAlertEngine:
    """Движок для обнаружения атак и аномалий"""

    def __init__(self):
        # Пороги для алертов
        self.thresholds = {
            'cpu': {'warning': 80, 'critical': 90},
            'memory': {'warning': 85, 'critical': 95},
            'disk': {'warning': 90, 'critical': 95},
            'network': {'warning': 1000, 'critical': 5000},  # KB/s
            'connections': {'warning': 100, 'critical': 500},
            'processes': {'warning': 200, 'critical': 500},
        }

    def check_host_metrics(self, host_id: int) -> List[Dict]:
        """Проверка метрик хоста на аномалии"""
        alerts = []

        # Получаем последние метрики (последние 5 минут)
        five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
        metrics = Metric.query.filter(
            Metric.host_id == host_id,
            Metric.timestamp >= five_minutes_ago
        ).all()

        if not metrics:
            return alerts

        # Группируем метрики по типам
        metric_by_type = {}
        for metric in metrics:
            if metric.metric_type not in metric_by_type:
                metric_by_type[metric.metric_type] = []
            metric_by_type[metric.metric_type].append(metric.value)

        host = Host.query.get(host_id)
        if not host:
            return alerts

        # Проверяем каждую метрику
        for metric_type, values in metric_by_type.items():
            if not values:
                continue

            avg_value = sum(values) / len(values)
            max_value = max(values)

            # Проверка порогов
            if metric_type in self.thresholds:
                thresholds = self.thresholds[metric_type]

                if max_value >= thresholds['critical']:
                    alerts.append({
                        'host_id': host_id,
                        'title': f'КРИТИЧЕСКИЙ: Высокая загрузка {metric_type.upper()}',
                        'description': f'{metric_type.upper()} хоста {host.name} достиг {max_value}% (порог: {thresholds["critical"]}%)',
                        'severity': AlertSeverity.CRITICAL.value,
                        'alert_type': f'{metric_type}_high',
                        'trigger_value': max_value,
                        'trigger_threshold': thresholds['critical'],
                        'alert_data': {  # ИСПРАВЛЕНО: было 'metadata'
                            'host_name': host.name,
                            'metric_type': metric_type,
                            'avg_value': avg_value,
                            'max_value': max_value,
                            'check_period': '5m'
                        }
                    })
                elif max_value >= thresholds['warning']:
                    alerts.append({
                        'host_id': host_id,
                        'title': f'ПРЕДУПРЕЖДЕНИЕ: Высокая загрузка {metric_type.upper()}',
                        'description': f'{metric_type.upper()} хоста {host.name} достиг {max_value}% (порог: {thresholds["warning"]}%)',
                        'severity': AlertSeverity.WARNING.value,
                        'alert_type': f'{metric_type}_high',
                        'trigger_value': max_value,
                        'trigger_threshold': thresholds['warning'],
                        'alert_data': {  # ИСПРАВЛЕНО: было 'metadata'
                            'host_name': host.name,
                            'metric_type': metric_type,
                            'avg_value': avg_value,
                            'max_value': max_value,
                            'check_period': '5m'
                        }
                    })

        return alerts

    def check_security_events(self, host_id: int, security_data: Dict) -> List[Dict]:
        """Проверка событий безопасности из метрик"""
        alerts = []

        host = Host.query.get(host_id)
        if not host:
            return alerts

        # Пример: обнаружение подозрительных процессов
        if 'suspicious_processes' in security_data:
            processes = security_data['suspicious_processes']
            if processes:
                alerts.append({
                    'host_id': host_id,
                    'title': 'Обнаружены подозрительные процессы',
                    'description': f'На хосте {host.name} найдены {len(processes)} подозрительных процесса',
                    'severity': AlertSeverity.CRITICAL.value,
                    'alert_type': 'suspicious_processes',
                    'trigger_value': len(processes),
                    'trigger_threshold': 0,
                    'alert_data': {  # ИСПРАВЛЕНО: было 'metadata'
                        'host_name': host.name,
                        'processes': processes,
                        'recommendation': 'Проверить процессы на наличие майнеров, бэкдоров'
                    }
                })

        return alerts

    def process_metrics_for_alerts(self, host_id: int, metrics_data: List[Dict]) -> List[Dict]:
        """Основной метод обработки метрик для алертов"""
        all_alerts = []

        # Проверяем базовые метрики
        all_alerts.extend(self.check_host_metrics(host_id))

        # Ищем данные безопасности в extra_data
        security_events = {}
        for metric in metrics_data:
            extra = metric.get('extra_data', {})
            for key in ['suspicious_processes', 'unusual_ports', 'failed_logins']:
                if key in extra:
                    security_events[key] = extra[key]

        all_alerts.extend(self.check_security_events(host_id, security_events))

        return all_alerts

    def save_alerts(self, alerts_data: List[Dict]):
        """Сохранение алертов в БД"""
        saved_alerts = []

        for alert_data in alerts_data:
            # Проверяем, нет ли уже открытого алерта такого типа
            existing_alert = Alert.query.filter_by(
                host_id=alert_data['host_id'],
                alert_type=alert_data['alert_type'],
                status=AlertStatus.OPEN.value
            ).first()

            if existing_alert:
                # Обновляем существующий алерт
                existing_alert.description = alert_data['description']
                existing_alert.trigger_value = alert_data.get('trigger_value')
                existing_alert.alert_data = alert_data.get('alert_data', {})  # ИСПРАВЛЕНО
            else:
                # Создаем новый алерт
                alert = Alert(
                    host_id=alert_data['host_id'],
                    title=alert_data['title'],
                    description=alert_data['description'],
                    severity=alert_data['severity'],
                    alert_type=alert_data['alert_type'],
                    trigger_value=alert_data.get('trigger_value'),
                    trigger_threshold=alert_data.get('trigger_threshold'),
                    alert_data=alert_data.get('alert_data', {})  # ИСПРАВЛЕНО
                )
                db.session.add(alert)
                saved_alerts.append(alert)

        try:
            db.session.commit()
            return saved_alerts
        except Exception as e:
            db.session.rollback()
            print(f"Ошибка сохранения алертов: {e}")
            return []


# Синглтон для использования в приложении
alert_engine = SecurityAlertEngine()