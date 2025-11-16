#!/bin/bash

# ReputationRecon Production Deployment Script
# For Ubuntu 24 LTS with HTTPS

set -e  # Exit on error

echo "=========================================="
echo "ReputationRecon Production Deployment"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}Please do not run this script as root. Run as a user with sudo privileges.${NC}"
   exit 1
fi

# Configuration
DOMAIN=""
EMAIL=""
APP_USER=$(whoami)
APP_DIR="$HOME/ReputationRecon"

# Get domain name
read -p "Enter your domain name (e.g., example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Domain name is required!${NC}"
    exit 1
fi

# Get email for Let's Encrypt
read -p "Enter your email for Let's Encrypt certificates: " EMAIL
if [ -z "$EMAIL" ]; then
    echo -e "${RED}Email is required!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Starting deployment for domain: $DOMAIN${NC}"
echo ""

# Step 1: Update system
echo -e "${YELLOW}[1/9] Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# Step 2: Install dependencies
echo -e "${YELLOW}[2/9] Installing system dependencies...${NC}"
sudo apt install -y \
    python3.12 \
    python3.12-venv \
    python3-pip \
    nodejs \
    npm \
    nginx \
    certbot \
    python3-certbot-nginx \
    git \
    sqlite3 \
    build-essential \
    ufw \
    supervisor

# Step 3: Configure firewall
echo -e "${YELLOW}[3/9] Configuring firewall...${NC}"
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

# Step 4: Check if repository exists
echo -e "${YELLOW}[4/9] Checking application directory...${NC}"
if [ ! -d "$APP_DIR" ]; then
    echo -e "${RED}Repository not found at $APP_DIR${NC}"
    echo "Please clone the repository first:"
    echo "  cd $HOME"
    echo "  git clone <repo-url> ReputationRecon"
    exit 1
fi

# Step 5: Setup Python backend
echo -e "${YELLOW}[5/9] Setting up Python backend...${NC}"
cd $APP_DIR
if [ ! -d "venv" ]; then
    python3.12 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Step 6: Setup Node.js frontend
echo -e "${YELLOW}[6/9] Building frontend...${NC}"
cd $APP_DIR/client
npm install
npm run build
cd $APP_DIR

# Step 7: Create systemd service
echo -e "${YELLOW}[7/9] Creating systemd service...${NC}"
sudo tee /etc/systemd/system/reputationrecon.service > /dev/null << EOF
[Unit]
Description=ReputationRecon FastAPI Backend
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$APP_DIR
ReadWritePaths=$HOME

[Install]
WantedBy=multi-user.target
EOF

# Step 8: Configure Nginx
echo -e "${YELLOW}[8/9] Configuring Nginx...${NC}"
sudo tee /etc/nginx/sites-available/reputationrecon > /dev/null << EOF
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;

    # SSL Configuration (will be updated by certbot)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/reputationrecon_access.log;
    error_log /var/log/nginx/reputationrecon_error.log;

    # Maximum upload size
    client_max_body_size 10M;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/json;

    # Serve static files from built frontend
    location / {
        root $APP_DIR/client/dist;
        try_files \$uri \$uri/ /index.html;
        index index.html;
    }

    # Serve logo.png
    location /logo.png {
        root $APP_DIR;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Proxy API requests to FastAPI backend
    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Proxy WebSocket connections
    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/reputationrecon /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx config
sudo nginx -t

# Step 9: Obtain SSL certificate
echo -e "${YELLOW}[9/9] Obtaining SSL certificate...${NC}"
sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email $EMAIL --redirect

# Enable and start services
echo -e "${YELLOW}Enabling and starting services...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable reputationrecon
sudo systemctl restart reputationrecon
sudo systemctl restart nginx

# Final checks
echo ""
echo -e "${GREEN}=========================================="
echo "Deployment Complete!"
echo "==========================================${NC}"
echo ""
echo "Checking service status..."
sudo systemctl status reputationrecon --no-pager -l
echo ""
echo -e "${GREEN}Your application should now be available at:${NC}"
echo -e "${GREEN}https://$DOMAIN${NC}"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo "1. Make sure your .env file is configured with API keys"
echo "2. Check logs with: sudo journalctl -u reputationrecon -f"
echo "3. Test SSL certificate: sudo certbot certificates"
echo ""
echo -e "${GREEN}Deployment script completed successfully!${NC}"

