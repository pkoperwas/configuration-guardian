#!/bin/bash
# Configuration Guardian v1.0 - Deployment Script
# Automated installation for RHEL/CentOS/Rocky Linux

set -e

echo "================================================"
echo "  Configuration Guardian v1.0 - Deployment"
echo "================================================"

# Install dependencies
echo "[1/6] Installing system dependencies..."
dnf install -y python3 python3-pip rsync openssh-clients

# Install Python packages
echo "[2/6] Installing Python dependencies..."
pip3 install flask

# Create directory structure
echo "[3/6] Creating directory structure..."
mkdir -p /opt/configuration-guardian/{config,data/storage,data/index,templates}

# Deploy application files
echo "[4/6] Deploying application files..."
cp app.py /opt/configuration-guardian/
mkdir -p /opt/configuration-guardian/templates
cp templates/index.html /opt/configuration-guardian/templates/
cp templates/login.html /opt/configuration-guardian/templates/
chmod +x /opt/configuration-guardian/app.py

# Setup systemd service
echo "[5/6] Configuring systemd service..."
cp configuration-guardian.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable configuration-guardian.service

# Start service
echo "[6/6] Starting Configuration Guardian service..."
systemctl start configuration-guardian.service

# Verify installation
echo ""
echo "================================================"
echo "  Installation Complete!"
echo "================================================"
echo ""
echo "Service Status:"
systemctl status configuration-guardian.service --no-pager
echo ""
echo "Access the web interface at:"
echo "  http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "Useful commands:"
echo "  systemctl status configuration-guardian    - Check service status"
echo "  systemctl restart configuration-guardian   - Restart service"
echo "  journalctl -u configuration-guardian -f    - View logs"
echo ""
