#!/bin/bash
set -e

# Install required dependencies
apt-get update
apt-get install -y build-essential libjansson-dev

# Create comp user and directories
useradd -r -s /bin/false comp || true
mkdir -p /opt/comp /var/log/comp
chown -R comp:comp /opt/comp /var/log/comp
chmod 755 /opt/comp

# Build C modules
cd /opt/comp/modules/c
make clean
make all

# Build Go binary
cd /opt/comp
go build -o comp cmd/comp/main.go

# Install systemd service
cp deploy/comp.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable comp
systemctl start comp

# Show status
systemctl status comp
echo "COMP server installation complete!"
echo "Check logs with: journalctl -u comp -f"
