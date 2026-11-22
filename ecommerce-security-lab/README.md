# E-Commerce Security Testing and Malware Simulation Laboratory

A Network Security project demonstrating security threats, detection, and incident response through two interconnected web applications.

## Project Overview

This project consists of two separate web applications:

1. **LabMart (Victim Website)** – A simulated e-commerce platform with product browsing, shopping cart, checkout, customer accounts, admin dashboard, and security monitoring.
2. **CyberSim Lab (Simulation Dashboard)** – A cybersecurity control panel used to demonstrate spyware, ransomware, and trojan attack simulations against LabMart.

The applications communicate through an authenticated REST API using HMAC signatures.

## Project Objectives

- Demonstrate common cybersecurity threats in an e-commerce environment.
- Understand how malware-related activities can affect online systems.
- Implement security monitoring and incident detection.
- Demonstrate authentication, authorization, and API security.
- Explore incident response and recovery procedures.
- Analyze network traffic using Wireshark.

## Features

### 1. LabMart – E-Commerce Website

- Product catalog and shopping cart.
- Customer registration and authentication.
- Checkout and order management.
- Midtrans Sandbox payment integration.
- Admin dashboard.
- Security event monitoring.
- Incident management.

### 2. CyberSim Lab – Security Simulation

**Spyware Simulation**
- Demonstrates simulated access to synthetic customer records.
- Displays data exposure events.
- Generates security alerts and incidents.

**Ransomware Simulation**
- Demonstrates simulated file-locking behavior.
- Uses a dedicated sandbox directory.
- Supports recovery and SHA-256 integrity verification.

**Trojan Simulation**
- Demonstrates simulated installation and network beacon activity.
- Generates suspicious connection events.
- Demonstrates command-and-control beacon detection.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application framework |
| SQLite | Database management |
| HTML | Web page structure |
| CSS | User interface styling |
| JavaScript | Frontend interactions |
| REST API | Communication between applications |
| HMAC-SHA256 | API request authentication |
| Midtrans Sandbox | Payment simulation |
| Wireshark | Network traffic analysis |

## Project Architecture

The project uses two independent Flask applications.

| Application | Local URL | Port |
|---|---|---|
| LabMart | http://127.0.0.1:5000 | 5000 |
| CyberSim Lab | http://127.0.0.1:5001 | 5001 |

Both applications maintain separate databases and authentication systems.

Communication between them uses an HMAC-authenticated REST API.

## Project Structure

```text
ecommerce-security-lab/
├── docs/
│   ├── PROJECT_DOCUMENTATION.md
│   └── DEMO_SCRIPT.md
├── lab/
│   ├── routes/
│   ├── security/
│   ├── templates/
│   └── simulations.py
├── shop/
│   ├── payments/
│   ├── routes/
│   ├── security/
│   ├── templates/
│   └── ransomware_sandbox.py
├── tests/
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── run_lab.py
├── run_shop.py
└── start_all.bat
```

## Installation

### Requirements

- Python 3.10 or newer
- Git
- Windows (for the provided startup script)

### 1. Clone the repository

```bash
git clone https://github.com/Abhiguell/network-security-project.git
cd network-security-project/ecommerce-security-lab
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Start both applications

```bash
start_all.bat
```

Alternatively, run the applications separately:

Terminal 1:

```bash
python run_shop.py
```

Terminal 2:

```bash
python run_lab.py
```

## Running the Simulation

1. Open LabMart at `http://127.0.0.1:5000`.
2. Open CyberSim Lab at `http://127.0.0.1:5001`.
3. Log in to the respective dashboards using the local demo accounts.
4. Select a simulation module.
5. Start the simulation.
6. Observe the security alerts and incidents in LabMart.
7. Use the Reset Environment function to restore the simulation state.

Default demo credentials are documented in the project documentation. They are for local educational use only and must be changed before any deployment.

## Security Features

The project demonstrates several defensive security mechanisms:

- Password hashing.
- Role-based access control.
- CSRF protection.
- SQL injection prevention through parameterized queries.
- XSS protection.
- Login attempt monitoring and account lockout.
- HMAC-signed API requests.
- Timestamp validation and nonce-based replay protection.
- Security event logging.
- Incident detection and recovery.

## Testing

Run the automated test suite:

```bash
python -m unittest discover -s tests -v
```

The project includes 29 tests covering:

- E-commerce functionality.
- Authentication and authorization.
- Payment integration behavior.
- API security.
- Spyware, ransomware, and trojan simulations.
- Simulation reset and recovery.

## Safety and Limitations

This project is designed strictly for educational purposes.

- Spyware simulations use synthetic customer records.
- Ransomware simulations operate only within a dedicated sandbox directory.
- No real customer information is accessed.
- No real files are encrypted or deleted.
- Trojan activity is simulated without persistence or remote access.
- Simulation requests require authenticated API access.

This laboratory should only be used in an authorized testing environment.

## Documentation

Additional project documentation:

- `docs/PROJECT_DOCUMENTATION.md` – Architecture, security implementation, API details, testing, and network analysis.
- `docs/DEMO_SCRIPT.md` – Demonstration instructions.

## Project Information

**Project:** E-Commerce Security Testing and Malware Simulation Laboratory

**Course:** Network Security

**Repository:** [GitHub - Abhiguell/network-security-project](https://github.com/Abhiguell/network-security-project)

---

*Developed as an educational Network Security project.*