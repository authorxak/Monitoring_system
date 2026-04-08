Вот **нормальный README** для вашего проекта на GitHub. Он написан профессионально, понятно и на английском (стандарт для open-source). Можете скопировать и заменить существующий.

---

```markdown
# Monitoring System

A lightweight, agent-based monitoring system for collecting system metrics, detecting attacks, and sending alerts across multiple servers.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Agent 1   │────▶│                  │     │             │
│ (kali-agent)│     │   Monitoring     │────▶│   Database  │
└─────────────┘     │     System       │     │   (SQLite)  │
┌─────────────┐     │   (server.py)    │     │             │
│   Agent 2   │────▶│                  │     └─────────────┘
│ (kali-agent)│     └──────────────────┘            │
└─────────────┘              │                       │
                             ▼                       ▼
                     ┌─────────────────────────────────────┐
                     │         Alert Engine                │
                     │  (email / webhook / logging)        │
                     └─────────────────────────────────────┘
```

## Features

- **Agent-based monitoring** – Deploy `kali-agent.py` on any server you want to monitor
- **Attack detection** – Real-time detection of suspicious activities
- **Alert engine** – Automatic alerts when thresholds are exceeded
- **Web interface** – Dashboard to visualize metrics (Flask-based)
- **Host checker** – Monitor host health and availability
- **Extensible** – Easy to add new metrics and detection rules

## Tech Stack

| Component | Technology |
|-----------|-------------|
| Backend | Python, Flask |
| Database | SQLite (can be extended to PostgreSQL) |
| Agent | Python (lightweight) |
| Alert Engine | Custom + SMTP / Webhooks |

## Project Structure

```
Monitoring_system/
├── server.py              # Main monitoring server
├── app.py                 # Flask web application
├── kali-agent.py          # Agent to run on monitored servers
├── config.py              # Configuration settings
├── models.py              # Database models
├── attack_detector.py     # Attack detection logic
├── alert_engine.py        # Alert handling
├── host_checker.py        # Host health checks
├── reset_db.py            # Database reset utility
├── extensions.py          # Flask extensions
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates for web UI
└── __init__.py            # Package initializer
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/authorxak/Monitoring_system.git
cd Monitoring_system
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Initialize the database

```bash
python reset_db.py
```

## Usage

### Start the Monitoring Server

```bash
python server.py
```

### Start the Web Interface (optional)

```bash
python app.py
```

### Run Agent on Monitored Servers

On each server you want to monitor:

```bash
python kali-agent.py --server <monitoring_server_ip> --hostname <server_name>
```

Example:

```bash
python kali-agent.py --server 192.168.1.100 --hostname web-server-01
```

## Configuration

Edit `config.py` to adjust:

- Database path
- Alert thresholds (CPU, memory, disk, etc.)
- SMTP settings for email alerts
- Webhook URLs
- Agent polling intervals

## Database Schema

| Table | Description |
|-------|-------------|
| `metrics` | System metrics (CPU, RAM, disk, network) |
| `alerts` | Generated alerts |
| `hosts` | Registered monitored hosts |
| `attacks` | Detected attack events |

## Example Commands

```bash
# Reset database
python reset_db.py

# Run agent with custom interval (seconds)
python kali-agent.py --server localhost --interval 30

# Run server in debug mode
python server.py --debug
```

## Roadmap

- [ ] Add PostgreSQL support
- [ ] Implement authentication for web interface
- [ ] Add Telegram/Slack alerts
- [ ] Docker support
- [ ] Prometheus metrics export

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License

## Author

**authorxak**

GitHub: [authorxak](https://github.com/authorxak)

---

## Notes

- The agent (`kali-agent.py`) must be able to reach the monitoring server over the network.
- Default database is SQLite – for production, consider migrating to PostgreSQL.
- Make sure to configure firewall rules to allow agent-server communication.

```
Скажите, и я сделаю русскую версию. Для GitHub обычно лучше английский — больше людей поймут.
