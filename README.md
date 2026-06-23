# Cloud Forensics Log Analyzer

A Python-based cloud forensic investigation platform designed to collect, analyze, and monitor cloud logs from multiple cloud environments. The system helps investigators identify suspicious activities, preserve digital evidence, generate forensic reports, and improve incident response capabilities.

## Project Overview

Cloud Forensics Log Analyzer is a cybersecurity and digital forensics project developed to support forensic investigations in cloud environments. The platform provides real-time log monitoring, evidence collection, integrity verification, alert generation, and forensic reporting through both desktop and web-based interfaces.

The project aims to simplify cloud investigations by automating log analysis and providing investigators with actionable insights through dashboards, alerts, and reports.

---

## Key Features

- Multi-cloud forensic log analysis
- Real-time activity monitoring
- Suspicious activity detection
- Evidence preservation and verification
- SHA-256 integrity checking
- User authentication and access control
- Automated alert notifications
- Forensic report generation
- Activity timeline reconstruction
- Desktop GUI and Web Dashboard
- Secure database storage

---

## Technologies Used

### Backend
- Python
- Flask

### Frontend
- HTML
- CSS
- JavaScript
- CustomTkinter

### Database
- SQLite

### Security
- SHA-256 Hashing
- bcrypt Authentication

### Cloud & APIs
- AWS SDK (Boto3)
- REST APIs

### Data Analysis
- Pandas
- Matplotlib

---

## System Architecture

The application consists of the following modules:

1. User Authentication
2. Log Acquisition
3. Evidence Integrity Verification
4. Log Analysis Engine
5. Alert Generation Module
6. Report Generation Module
7. Database Management
8. Dashboard & Visualization

---

## Workflow

1. User logs into the system.
2. Cloud logs are collected from supported sources.
3. Logs are parsed and analyzed.
4. Suspicious activities are detected.
5. Alerts are generated.
6. Evidence integrity is verified.
7. Forensic reports are generated.
8. Investigators review findings through the dashboard.

---

## Project Structure

```text
Cloud-Forensics-Log-Analyzer/
│
├── backend/
├── frontend/
├── templates/
├── static/
├── screenshots/
├── docs/
│   └── Project_Report.pdf
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Screenshots

### Login Page

Add screenshot here

### Dashboard

Add screenshot here

### Log Analysis

Add screenshot here

### Alert Management

Add screenshot here

### Forensic Report

Add screenshot here

---

## Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/cloud-forensics-log-analyzer.git
```

### Navigate to Project Folder

```bash
cd cloud-forensics-log-analyzer
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

---

## Security Features

- Password hashing using bcrypt
- Secure user authentication
- Evidence integrity verification
- Role-based access control
- Secure forensic data storage
- Audit logging

---

## Future Improvements

- AI-assisted threat detection
- Advanced anomaly detection
- Kubernetes log support
- SIEM integration
- Threat intelligence feeds
- Cloud-native deployment

---

## Academic Project

This project was developed as part of the B.Sc Cyber Forensics program at Jai Bharath Arts and Science College.

---

## Author

Your Name

Cyber Forensics Student

GitHub: https://github.com/yourusername

LinkedIn: Add Your LinkedIn Profile
