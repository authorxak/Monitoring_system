import io
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file
from attack_detector import attack_detector

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from config import Config
from extensions import db, cors
from models import Host, Metric

from alert_engine import alert_engine
from models import Alert, AlertStatus, AlertSeverity
# В импортах добавьте:
from host_checker import host_checker
import threading
import time


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    cors.init_app(app)

    return app


app = create_app()


# Добавьте новый эндпоинт для приема логов
@app.route('/api/v1/logs', methods=['POST'])
def receive_logs():
    """Прием логов от агентов для анализа атак"""
    data = request.json

    if not data or 'host_id' not in data or 'logs' not in data:
        return jsonify({'error': 'Invalid data format'}), 400

    host = Host.query.get(data['host_id'])
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    # Анализируем логи на атаки
    detected_attacks = attack_detector.process_logs_for_attacks(host.id, data['logs'])

    # Сохраняем обнаруженные атаки как алерты
    saved_alerts = []
    for attack in detected_attacks:
        alert = Alert(
            host_id=host.id,
            title=attack['title'],
            description=attack['description'],
            severity=attack['severity'],
            status=AlertStatus.OPEN.value,
            alert_type=attack['alert_type'],
            trigger_value=attack['trigger_value'],
            trigger_threshold=attack['trigger_threshold'],
            alert_data=attack['alert_data']
        )
        db.session.add(alert)
        saved_alerts.append(alert.to_dict())

    if saved_alerts:
        db.session.commit()

    return jsonify({
        'message': 'Logs received and analyzed',
        'attacks_detected': len(detected_attacks),
        'alerts_created': len(saved_alerts)
    })


# Эндпоинт для получения статистики атак
@app.route('/api/v1/attacks/stats', methods=['GET'])
def get_attack_stats():
    """Статистика по обнаруженным атакам"""
    host_id = request.args.get('host_id')

    stats = attack_detector.get_attack_stats(
        int(host_id) if host_id else None
    )

    return jsonify(stats)


# Эндпоинт для тестирования атак (демо)
@app.route('/api/v1/attacks/test', methods=['POST'])
def test_attack_detection():
    """Тестовая отправка логов атак"""
    test_logs = {
        'ssh_logs': [
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '192.168.1.100',
                'message': 'Failed password for root from 192.168.1.100 port 22 ssh2'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '192.168.1.100',
                'message': 'Failed password for admin from 192.168.1.100 port 22 ssh2'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '192.168.1.100',
                'message': 'Failed password for user from 192.168.1.100 port 22 ssh2'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '192.168.1.100',
                'message': 'Failed password for test from 192.168.1.100 port 22 ssh2'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '192.168.1.100',
                'message': 'Failed password for guest from 192.168.1.100 port 22 ssh2'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '192.168.1.100',
                'message': 'Failed password for root from 192.168.1.100 port 22 ssh2'
            }
        ],
        'connection_logs': [
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 22,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 80,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 443,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 21,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 25,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 3389,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 8080,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 3306,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 5432,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 27017,
                'protocol': 'TCP'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '10.0.0.50',
                'destination_port': 6379,
                'protocol': 'TCP'
            }
        ],
        'web_logs': [
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '172.16.0.10',
                'url': '/index.php?id=1 OR 1=1',
                'user_agent': 'Mozilla/5.0'
            },
            {
                'timestamp': datetime.utcnow(),
                'source_ip': '172.16.0.20',
                'url': '/search?q=<script>alert("xss")</script>',
                'user_agent': 'Mozilla/5.0'
            }
        ]
    }

    # Используем первый доступный хост
    host = Host.query.first()
    if not host:
        return jsonify({'error': 'No hosts available'}), 400

    response = receive_logs()

    # Получаем статистику
    stats = attack_detector.get_attack_stats(host.id)

    return jsonify({
        'message': 'Test attack logs sent',
        'host_id': host.id,
        'attacks_detected': stats['total_attacks'],
        'details': stats
    })

# После создания приложения добавьте фоновую задачу
def start_background_tasks():
    """Запуск фоновых задач"""

    def check_hosts_periodically():
        """Периодическая проверка хостов"""
        while True:
            try:
                with app.app_context():
                    host_checker.check_all_hosts_status()
                    host_checker.cleanup_old_alerts()
            except Exception as e:
                print(f"Ошибка в фоновой задаче: {e}")

            # Проверяем каждую минуту
            time.sleep(60)

    # Запускаем в отдельном потоке
    thread = threading.Thread(target=check_hosts_periodically, daemon=True)
    thread.start()
    print("✅ Фоновая проверка хостов запущена")


with app.app_context():
    db.create_all()
    start_background_tasks()


@app.route('/')
def index():
    """Главная страница с дашбордом"""

    hosts = Host.query.all()
    now = datetime.utcnow()

    # Статистика
    total_hosts = len(hosts)

    # Считаем активные хосты (последние 5 минут)
    active_hosts = 0
    for host in hosts:
        if host.last_seen:
            minutes_ago = (now - host.last_seen).total_seconds() / 60
            if minutes_ago <= 5:
                active_hosts += 1

    # Последние метрики с жадной загрузкой хостов
    recent_metrics = Metric.query.options(db.joinedload(Metric.host_obj)).order_by(Metric.timestamp.desc()).limit(
        10).all()

    # Получаем ВСЕ алерты для фильтрации в шаблоне
    all_alerts = Alert.query.all()

    return render_template('index.html',
                           hosts=hosts,
                           total_hosts=total_hosts,
                           active_hosts=active_hosts,
                           recent_metrics=recent_metrics,
                           now=now,
                           alerts=all_alerts)

@app.route('/api/v1/hosts/check-status', methods=['POST'])
def check_hosts_status():
    """Ручная проверка статуса всех хостов"""
    inactive_hosts = host_checker.check_all_hosts_status()
    host_checker.cleanup_old_alerts()

    return jsonify({
        'message': 'Host status checked',
        'inactive_hosts': inactive_hosts,
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/api/v1/hosts/<int:host_id>/status', methods=['GET'])
def get_host_status(host_id):
    """Получить детальный статус хоста"""
    host = Host.query.get_or_404(host_id)

    host.update_status()
    minutes_since_last_seen = host.get_minutes_since_last_seen()

    return jsonify({
        'host_id': host.id,
        'host_name': host.name,
        'is_active': host.is_active,
        'last_seen': host.last_seen.isoformat() if host.last_seen else None,
        'minutes_since_last_seen': minutes_since_last_seen,
        'status': 'active' if host.is_active else 'inactive',
        'recommendation': 'OK' if host.is_active else f'Host inactive for {minutes_since_last_seen} minutes'
    })

@app.route('/hosts')
def hosts_page():
    """Страница со списком хостов"""
    hosts = Host.query.all()
    return render_template('hosts.html', hosts=hosts)


@app.route('/metrics/<int:host_id>')
def metrics_page(host_id):
    """Страница с метриками конкретного хоста"""
    host = Host.query.get_or_404(host_id)
    metric_types = db.session.query(Metric.metric_type).filter(
        Metric.host_id == host_id
    ).distinct().all()
    metric_types = [m[0] for m in metric_types]

    return render_template('metrics.html',
                           host=host,
                           metric_types=metric_types)


@app.route('/dashboard')
def dashboard():
    """Дашборд с графиками"""
    hosts = Host.query.all()
    return render_template('dashboard.html', hosts=hosts)


@app.route('/api/v1/register', methods=['POST'])
def register_host():
    """Регистрация нового хоста"""
    data = request.json
    existing_host = Host.query.filter_by(ip_address=data['ip_address']).first()

    if existing_host:
        existing_host.name = data.get('name', existing_host.name)
        existing_host.hostname = data.get('hostname', existing_host.hostname)
        existing_host.os = data.get('os', existing_host.os)
        existing_host.is_active = True
        existing_host.last_seen = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Host updated', 'host': existing_host.to_dict()})


    new_host = Host(
        name=data['name'],
        ip_address=data['ip_address'],
        hostname=data.get('hostname', ''),
        os=data.get('os', ''),
        is_active=True,
        last_seen=datetime.utcnow()
    )

    db.session.add(new_host)
    db.session.commit()

    return jsonify({'message': 'Host registered', 'host': new_host.to_dict()}), 201


#------------------------------------------------------------------------------------------

# Добавьте после функции receive_metrics
@app.route('/api/v1/metrics', methods=['POST'])
def receive_metrics():
    """Прием метрик от агентов"""
    data = request.json

    if not data or 'host_id' not in data or 'metrics' not in data:
        return jsonify({'error': 'Invalid data format'}), 400

    host = Host.query.get(data['host_id'])
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    # Обновляем время последней активности
    host.last_seen = datetime.utcnow()
    host.is_active = True

    # Сохраняем метрики
    metrics = data['metrics']
    saved_metrics = []

    for metric_data in metrics:
        metric = Metric(
            host_id=host.id,
            metric_type=metric_data['type'],
            value=float(metric_data['value']),
            unit=metric_data.get('unit', '%'),
            extra_data=metric_data.get('extra', {})
        )
        db.session.add(metric)
        saved_metrics.append(metric.to_dict())

    db.session.commit()

    # 🚨 ПОСЛЕ сохранения метрик - проверяем алерты
    try:
        alerts = alert_engine.process_metrics_for_alerts(host.id, saved_metrics)
        if alerts:
            alert_engine.save_alerts(alerts)
            print(f"🚨 Обнаружено {len(alerts)} алертов для хоста {host.name}")
    except Exception as e:
        print(f"⚠️ Ошибка при проверке алертов: {e}")

    return jsonify({'message': 'Metrics received', 'count': len(saved_metrics)})


# 🚨 НОВЫЕ API ЭНДПОИНТЫ ДЛЯ АЛЕРТОВ

@app.route('/api/v1/alerts', methods=['GET'])
def get_alerts():
    """Получение всех алертов"""
    status = request.args.get('status')
    severity = request.args.get('severity')
    host_id = request.args.get('host_id')

    query = Alert.query

    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)
    if host_id:
        query = query.filter_by(host_id=host_id)

    # Сортировка: сначала критические, потом новые
    alerts = query.order_by(
        db.case(
            (Alert.severity == AlertSeverity.CRITICAL.value, 1),
            (Alert.severity == AlertSeverity.WARNING.value, 2),
            (Alert.severity == AlertSeverity.INFO.value, 3),
            else_=4
        ),
        Alert.created_at.desc()
    ).all()

    return jsonify([alert.to_dict() for alert in alerts])


@app.route('/api/v1/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Статистика по алертам"""
    total = Alert.query.count()
    open_alerts = Alert.query.filter_by(status=AlertStatus.OPEN.value).count()
    critical_alerts = Alert.query.filter_by(
        severity=AlertSeverity.CRITICAL.value,
        status=AlertStatus.OPEN.value
    ).count()

    # Алерты по хостам
    hosts_with_alerts = db.session.query(
        Host.name,
        db.func.count(Alert.id).label('alert_count')
    ).join(Alert).group_by(Host.id).all()

    return jsonify({
        'total_alerts': total,
        'open_alerts': open_alerts,
        'critical_alerts': critical_alerts,
        'hosts_with_alerts': [
            {'host_name': name, 'alert_count': count}
            for name, count in hosts_with_alerts
        ]
    })


@app.route('/api/v1/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Подтверждение алерта"""
    alert = Alert.query.get_or_404(alert_id)
    alert.acknowledge()
    db.session.commit()
    return jsonify({'message': 'Alert acknowledged', 'alert': alert.to_dict()})


@app.route('/api/v1/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Закрытие алерта"""
    alert = Alert.query.get_or_404(alert_id)
    alert.resolve()
    db.session.commit()
    return jsonify({'message': 'Alert resolved', 'alert': alert.to_dict()})


@app.route('/api/v1/alerts/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    """Удаление алерта"""
    alert = Alert.query.get_or_404(alert_id)
    db.session.delete(alert)
    db.session.commit()
    return jsonify({'message': 'Alert deleted'})


@app.route('/api/v1/alerts/bulk/resolve', methods=['POST'])
def resolve_bulk_alerts():
    """Массовое закрытие алертов"""
    data = request.json
    alert_ids = data.get('alert_ids', [])

    resolved = 0
    for alert_id in alert_ids:
        alert = Alert.query.get(alert_id)
        if alert:
            alert.resolve()
            resolved += 1

    db.session.commit()
    return jsonify({'message': f'Resolved {resolved} alerts'})


# 🚨 HTML страница для алертов
@app.route('/alerts')
def alerts_page():
    """Страница с алертами"""
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(50).all()

    # Статистика
    total_alerts = len(alerts)
    critical_alerts = len([a for a in alerts if a.severity == AlertSeverity.CRITICAL.value])
    open_alerts = len([a for a in alerts if a.status == AlertStatus.OPEN.value])

    return render_template('alerts.html',
                           alerts=alerts,
                           total_alerts=total_alerts,
                           critical_alerts=critical_alerts,
                           open_alerts=open_alerts)


@app.route('/api/v1/metrics/bulk', methods=['POST'])
def receive_bulk_metrics():
    """Прием метрик в пакетном режиме"""
    data = request.json

    if not isinstance(data, list):
        return jsonify({'error': 'Expected list of metric objects'}), 400

    for item in data:
        host_ip = item.get('ip_address')
        metrics = item.get('metrics', [])

        if not host_ip:
            continue


        host = Host.query.filter_by(ip_address=host_ip).first()
        if not host:
            host = Host(
                name=host_ip,
                ip_address=host_ip,
                is_active=True
            )
            db.session.add(host)

        host.last_seen = datetime.utcnow()
        host.is_active = True

        for metric_data in metrics:
            metric = Metric(
                host_id=host.id,
                metric_type=metric_data['type'],
                value=float(metric_data['value']),
                unit=metric_data.get('unit', '%'),
                timestamp=datetime.fromisoformat(metric_data.get('timestamp', datetime.utcnow().isoformat())),
                extra_data=metric_data.get('extra', {})
            )
            db.session.add(metric)

    db.session.commit()

    return jsonify({'message': 'Bulk metrics received'})


@app.route('/api/v1/hosts', methods=['GET'])
def get_hosts():
    """Получение списка хостов"""
    hosts = Host.query.all()
    return jsonify([host.to_dict() for host in hosts])


@app.route('/api/v1/hosts/<int:host_id>', methods=['GET'])
def get_host(host_id):
    """Получение информации о хосте"""
    host = Host.query.get_or_404(host_id)
    return jsonify(host.to_dict())


@app.route('/api/v1/hosts/<int:host_id>', methods=['DELETE'])
def delete_host(host_id):
    """Удаление хоста"""
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    return jsonify({'message': 'Host deleted'})


@app.route('/api/v1/metrics/host/<int:host_id>', methods=['GET'])
def get_host_metrics(host_id):
    """Получение метрик хоста"""
    host = Host.query.get_or_404(host_id)

    # Параметры запроса
    metric_type = request.args.get('type')
    hours = int(request.args.get('hours', 24))
    limit = int(request.args.get('limit', 1000))

    # Базовый запрос
    query = Metric.query.filter_by(host_id=host_id)

    # Фильтр по типу метрики
    if metric_type:
        query = query.filter_by(metric_type=metric_type)

    # Фильтр по времени
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    query = query.filter(Metric.timestamp >= time_threshold)

    # Сортировка и лимит
    metrics = query.order_by(Metric.timestamp.desc()).limit(limit).all()

    return jsonify([metric.to_dict() for metric in metrics])


@app.route('/api/v1/metrics/types/<int:host_id>', methods=['GET'])
def get_metric_types(host_id):
    """Получение доступных типов метрик для хоста"""
    types = db.session.query(Metric.metric_type).filter(
        Metric.host_id == host_id
    ).distinct().all()

    return jsonify([t[0] for t in types])


@app.route('/api/v1/metrics/summary/<int:host_id>', methods=['GET'])
def get_metrics_summary(host_id):
    """Получение сводки по метрикам"""
    hours = int(request.args.get('hours', 1))
    time_threshold = datetime.utcnow() - timedelta(hours=hours)

    # Группируем по типу метрики
    metrics = Metric.query.filter(
        Metric.host_id == host_id,
        Metric.timestamp >= time_threshold
    ).all()

    summary = {}
    for metric in metrics:
        if metric.metric_type not in summary:
            summary[metric.metric_type] = {
                'values': [],
                'unit': metric.unit
            }
        summary[metric.metric_type]['values'].append(metric.value)

    # Вычисляем статистику
    result = {}
    for metric_type, data in summary.items():
        values = data['values']
        if values:
            result[metric_type] = {
                'avg': sum(values) / len(values),
                'min': min(values),
                'max': max(values),
                'latest': values[-1],
                'unit': data['unit'],
                'count': len(values)
            }

    return jsonify(result)


@app.route('/api/v1/plot/<int:host_id>', methods=['GET'])
def plot_metrics(host_id):
    """Генерация графика метрик"""
    metric_type = request.args.get('type', 'cpu')
    hours = int(request.args.get('hours', 24))

    # Получаем данные
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    metrics = Metric.query.filter(
        Metric.host_id == host_id,
        Metric.metric_type == metric_type,
        Metric.timestamp >= time_threshold
    ).order_by(Metric.timestamp.asc()).all()

    if not metrics:
        # Возвращаем пустой график
        plt.figure(figsize=(12, 6))
        plt.text(0.5, 0.5, 'No data available',
                 horizontalalignment='center', verticalalignment='center',
                 transform=plt.gca().transAxes, fontsize=14)
        plt.title(f'{metric_type.upper()} Usage - Last {hours} hours')
        plt.xlabel('Time')
        plt.ylabel('Usage (%)')

        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100)
        plt.close()
        buf.seek(0)
        return send_file(buf, mimetype='image/png')

    # Подготавливаем данные для графика
    timestamps = [m.timestamp for m in metrics]
    values = [m.value for m in metrics]
    unit = metrics[0].unit

    # Создаем график
    plt.figure(figsize=(12, 6))
    plt.plot(timestamps, values, 'b-', linewidth=2)
    plt.fill_between(timestamps, values, alpha=0.3)

    # Форматируем график
    plt.title(f'{metric_type.upper()} Usage - Last {hours} hours')
    plt.xlabel('Time')
    plt.ylabel(f'Usage ({unit})')
    plt.grid(True, alpha=0.3)

    # Форматирование времени на оси X
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=max(1, hours // 6)))
    plt.xticks(rotation=45)

    plt.tight_layout()

    # Сохраняем в буфер
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    plt.close()
    buf.seek(0)

    # Возвращаем изображение
    return send_file(buf, mimetype='image/png')


@app.route('/api/v1/plot/comparison', methods=['GET'])
def plot_comparison():
    """Сравнение метрик нескольких хостов"""
    host_ids = request.args.getlist('host_id')
    metric_type = request.args.get('type', 'cpu')
    hours = int(request.args.get('hours', 1))

    if not host_ids:
        return jsonify({'error': 'No hosts specified'}), 400

    plt.figure(figsize=(12, 6))

    colors = ['#007bff', '#28a745', '#ffc107', '#dc3545', '#6f42c1']

    for i, host_id in enumerate(host_ids[:5]):  # Ограничиваем 5 хостами
        host = Host.query.get(host_id)
        if not host:
            continue

        # Получаем данные
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        metrics = Metric.query.filter(
            Metric.host_id == host_id,
            Metric.metric_type == metric_type,
            Metric.timestamp >= time_threshold
        ).order_by(Metric.timestamp.asc()).all()

        if not metrics:
            continue

        timestamps = [m.timestamp for m in metrics]
        values = [m.value for m in metrics]

        plt.plot(timestamps, values,
                 label=f'{host.name} ({host.ip_address})',
                 color=colors[i % len(colors)],
                 linewidth=2)

    plt.title(f'{metric_type.upper()} Comparison - Last {hours} hours')
    plt.xlabel('Time')
    plt.ylabel('Usage (%)')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Сохраняем в буфер
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    plt.close()
    buf.seek(0)

    return send_file(buf, mimetype='image/png')


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Проверка здоровья системы"""
    total_hosts = Host.query.count()
    total_metrics = Metric.query.count()

    # Проверяем активные хосты (были активны последние 5 минут)
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    active_hosts = Host.query.filter(
        Host.last_seen >= five_minutes_ago,
        Host.is_active == True
    ).count()

    return jsonify({
        'status': 'healthy',
        'total_hosts': total_hosts,
        'active_hosts': active_hosts,
        'total_metrics': total_metrics,
        'timestamp': datetime.utcnow().isoformat()
    })


# ==================== UTILITY ENDPOINTS ====================

@app.route('/api/v1/cleanup', methods=['POST'])
def cleanup_old_data():
    """Очистка старых данных (административная функция)"""
    days_to_keep = request.json.get('days', 30)

    cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

    # Удаляем старые метрики
    deleted_count = Metric.query.filter(Metric.timestamp < cutoff_date).delete()

    # Деактивируем хосты, которых не было больше недели
    week_ago = datetime.utcnow() - timedelta(days=7)
    inactive_hosts = Host.query.filter(Host.last_seen < week_ago).update({'is_active': False})

    db.session.commit()

    return jsonify({
        'message': 'Cleanup completed',
        'deleted_metrics': deleted_count,
        'deactivated_hosts': inactive_hosts
    })


# ==================== SIMPLE TEST ENDPOINTS ====================

@app.route('/api/v1/test/data', methods=['GET'])
def generate_test_data():
    """Генерация тестовых данных для демонстрации"""
    import random
    from datetime import datetime, timedelta

    # Создаем тестовый хост если его нет
    host = Host.query.filter_by(ip_address='192.168.1.100').first()
    if not host:
        host = Host(
            name='Test Server',
            ip_address='192.168.1.100',
            hostname='test-server',
            os='Linux',
            is_active=True,
            last_seen=datetime.utcnow()
        )
        db.session.add(host)
        db.session.commit()

    # Генерируем тестовые метрики за последние 24 часа
    now = datetime.utcnow()
    for i in range(24 * 12):  # Каждые 5 минут в течение 24 часов
        timestamp = now - timedelta(minutes=i * 5)

        # CPU
        cpu_metric = Metric(
            host_id=host.id,
            metric_type='cpu',
            value=random.uniform(10, 80),
            unit='%',
            timestamp=timestamp
        )
        db.session.add(cpu_metric)

        # Memory
        memory_metric = Metric(
            host_id=host.id,
            metric_type='memory',
            value=random.uniform(30, 90),
            unit='%',
            timestamp=timestamp
        )
        db.session.add(memory_metric)

        # Disk
        disk_metric = Metric(
            host_id=host.id,
            metric_type='disk',
            value=random.uniform(40, 95),
            unit='%',
            timestamp=timestamp
        )
        db.session.add(disk_metric)

    db.session.commit()

    return jsonify({
        'message': 'Test data generated',
        'host_id': host.id,
        'metrics_count': 24 * 12 * 3
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)