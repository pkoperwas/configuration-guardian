# 🛡️ Configuration Guardian

![Language](https://img.shields.io/badge/Language-Python-blue)
![UI](https://img.shields.io/badge/GUI-Web%20UI-brightgreen)
![Port](https://img.shields.io/badge/Port-8080-orange)
![Status](https://img.shields.io/badge/Status-Production--Ready-success)

**Configuration Guardian** is a modern Python-based web application for **managing configuration backups from remote servers**.  
It runs as a service on port **8080** and provides a clean, intuitive **web GUI**.


---

## 📸 Screenshots

### Login page
![1](screenshots/1.jpg)

### Files overview
![2](screenshots/2.jpg)

### ssh-key management
![3](screenshots/3.jpg)

### node configuration
![4](screenshots/4.jpg)

---

## ⚡ Features

🟢 Web-based GUI for managing backups (default login admin/admin)   
🟢 Scheduled (cyclic) synchronizations  
🟢 Backup from multiple remote servers  
🟢 Multiple versions (retention of copies)  
🟢 One-click restore from GUI  
🟢 Runs as a systemd service on port **8080**  
🟢 Docker and docker-compose support

---

## 🔧 How It Works

🔹 The app runs as a service on port `8080`  
🔹 You add servers and paths to back up in the GUI  
🔹 A scheduler performs periodic sync jobs  
🔹 Each backup is versioned  
🔹 Restore can be triggered with one click

---

## ⚠️ Limitations

🔴 No native LDAP/SSO authentication yet  
🔴 Backup works in agentless pull mode over SSH  
🔴 No encryption at rest (transport is secured)

---

## 💻 Installation (bare metal / VM)

### 📦 Deploy from repository

```bash
git clone https://github.com/pkoperwas/configuration-guardian.git
cd configuration-guardian
bash deploy.sh
```

The script will:
- install dependencies
- create and install a systemd unit file
- start the service

### ▶ Service management

```bash
systemctl status configuration-guardian
systemctl restart configuration-guardian
```

### 🌐 Access

```
http://<SERVER_IP>:8080
```

---

## 🐳 Docker

The official Docker image is available on Docker Hub:  
👉 https://hub.docker.com/r/pkoperwas/configuration-guardian

---

### ▶ Run from Docker Hub

```bash
docker pull pkoperwas/configuration-guardian:latest

docker run -d \
  --name configuration-guardian \
  -p 8080:8080 \
  pkoperwas/configuration-guardian:latest
```

Then open in your browser:

```
http://<HOST_IP>:8080
```

---

### 📦 docker-compose

```yaml
version: "3.8"
services:
  configuration-guardian:
    image: pkoperwas/configuration-guardian:latest
    container_name: configuration-guardian
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

Start it with:

```bash
docker-compose up -d
```

---

### 📄 Local build (optional)

If you want to build the image locally:

```bash
docker build -t configuration-guardian .
docker run -d -p 8080:8080 configuration-guardian
```
---

## 💡 Use Cases

✅ Linux server configuration backup  
✅ Backup of /etc, /opt/app/config, playbooks, etc.  
✅ Fast restore after failure  
✅ Change auditing over time  


---
Traffic Stats     
![Badge](https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2Fpkoperwas%2Fconfiguration-guardian&label=&icon=bar-chart-fill&color=%236edff6&message=&style=flat&tz=UTC)

