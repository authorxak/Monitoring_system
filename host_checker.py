# host_checker.py
from datetime import datetime, timedelta
from models import db, Host, Alert, AlertSeverity


class HostStatusChecker:
    """Проверка статуса хостов"""

    def __init__(self, inactive_threshold_minutes=5):
        self.inactive_threshold = inactive_threshold_minutes

    def check_all_hosts_status(self):
        """Проверить статус всех хостов"""
        hosts = Host.query.all()
        inactive_hosts = []

        for host in hosts:
            # Обновляем статус хоста
            host.update_status()

            # Если хост стал неактивным
            if not host.is_active:
                minutes_inactive = host.get_minutes_since_last_seen()

                # Проверяем, есть ли уже алерт о неактивности
                existing_alert = Alert.query.filter_by(
                    host_id=host.id,
                    alert_type='host_inactive',
                    status='open'
                ).first()

                if not existing_alert and minutes_inactive > self.inactive_threshold:
                    # Создаем алерт о неактивности хоста
                    alert = Alert(
                        host_id=host.id,
                        title=f'Хост не отвечает: {host.name}',
                        description=f'Хост {host.name} ({host.ip_address}) не отправлял метрики более {int(minutes_inactive)} минут',
                        severity=AlertSeverity.WARNING.value,
                        alert_type='host_inactive',
                        trigger_value=minutes_inactive,
                        trigger_threshold=self.inactive_threshold,
                        alert_data={
                            'host_name': host.name,
                            'ip_address': host.ip_address,
                            'minutes_inactive': minutes_inactive,
                            'last_seen': host.last_seen.isoformat() if host.last_seen else None
                        }
                    )
                    db.session.add(alert)
                    inactive_hosts.append(host.name)

        db.session.commit()

        if inactive_hosts:
            print(f"🚨 Обнаружены неактивные хосты: {', '.join(inactive_hosts)}")

        return inactive_hosts

    def cleanup_old_alerts(self):
        """Очистка старых алертов о неактивности, если хост снова активен"""
        inactive_alerts = Alert.query.filter_by(
            alert_type='host_inactive',
            status='open'
        ).all()

        for alert in inactive_alerts:
            host = Host.query.get(alert.host_id)
            if host and host.is_active:
                alert.resolve()
                print(f"✅ Хост {host.name} снова активен, алерт закрыт")

        db.session.commit()


# Синглтон для использования
host_checker = HostStatusChecker()