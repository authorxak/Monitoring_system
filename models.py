from datetime import datetime
from enum import Enum
from extensions import db

class AlertSeverity(Enum):
    """Уровни серьезности алертов"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class AlertStatus(Enum):
    """Статусы алертов"""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"

class Host(db.Model):
    """Модель хоста"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    hostname = db.Column(db.String(100))
    os = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Связь с метриками
    metrics = db.relationship('Metric', back_populates='host_obj', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'os': self.os,
            'is_active': self.is_active,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def update_status(self):
        """Обновить статус хоста на основе последней активности"""
        from datetime import datetime, timedelta

        if not self.last_seen:
            self.is_active = False
            return

        # Считаем хост активным, если был online в последние 5 минут
        five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
        self.is_active = self.last_seen >= five_minutes_ago

    def get_minutes_since_last_seen(self):
        """Получить количество минут с последней активности"""
        from datetime import datetime

        if not self.last_seen:
            return None

        delta = datetime.utcnow() - self.last_seen
        return round(delta.total_seconds() / 60, 1)

class Metric(db.Model):
    """Модель метрик"""
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    metric_type = db.Column(db.String(50), nullable=False)
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), default='%')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    extra_data = db.Column(db.JSON)

    # Используем back_populates вместо backref
    host_obj = db.relationship('Host', back_populates='metrics')

    def to_dict(self):
        timestamp_str = None
        if self.timestamp:
            timestamp_str = self.timestamp.isoformat()

        return {
            'id': self.id,
            'host_id': self.host_id,
            'metric_type': self.metric_type,
            'value': self.value,
            'unit': self.unit,
            'timestamp': timestamp_str,
            'extra_data': self.extra_data,
            'host': self.host_obj.to_dict() if self.host_obj else None
        }

# ⚠️ ВАЖНО: ОСТАВЬТЕ ТОЛЬКО ЭТУ МОДЕЛЬ ALERT (УДАЛИТЕ ДУБЛИКАТ)
class Alert(db.Model):
    """Модель для хранения алертов"""
    __tablename__ = 'alert'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='open')
    alert_type = db.Column(db.String(50), nullable=False)
    trigger_value = db.Column(db.Float)
    trigger_threshold = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    alert_data = db.Column(db.JSON)

    # Связь с хостами
    host = db.relationship('Host', backref='alerts')

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'host_name': self.host.name if self.host else None,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'alert_type': self.alert_type,
            'trigger_value': self.trigger_value,
            'trigger_threshold': self.trigger_threshold,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'alert_data': self.alert_data,
            'duration': self.get_duration()
        }

    def get_duration(self):
        """Получить продолжительность алерта в секундах"""
        if self.resolved_at and self.created_at:
            return (self.resolved_at - self.created_at).total_seconds()
        elif self.created_at:
            return (datetime.utcnow() - self.created_at).total_seconds()
        return 0j