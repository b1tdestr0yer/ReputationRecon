# Production Deployment Guide - Ubuntu 24 LTS with HTTPS

This guide will help you deploy ReputationRecon to a production server running Ubuntu 24 LTS with HTTPS certificates.

## Prerequisites

- Ubuntu 24 LTS server with root/sudo access
- Domain name pointing to your server's IP address
- SSH access to the server

## Step 1: Initial Server Setup

### 1.1 Update System Packages

```bash
sudo apt update && sudo apt upgrade -y
```

### 1.2 Install Required System Packages

```bash
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
```

### 1.3 Configure Firewall

```bash
# Allow SSH (important - do this first!)
sudo ufw allow OpenSSH

# Allow HTTP and HTTPS
sudo ufw allow 'Nginx Full'

# Enable firewall
sudo ufw --force enable

# Check status
sudo ufw status
```

## Step 2: Create Application User

```bash
# Create a dedicated user for the application
sudo adduser --disabled-password --gecos "" reputationrecon
sudo usermod -aG sudo reputationrecon

# Switch to the application user
sudo su - reputationrecon
```

## Step 3: Clone and Setup Application

### 3.1 Clone Repository

```bash
cd /home/reputationrecon
git clone <your-repository-url> ReputationRecon
cd ReputationRecon
```

### 3.2 Setup Python Backend

```bash
# Create virtual environment
python3.12 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3 Setup Node.js Frontend

```bash
cd client

# Install Node.js dependencies
npm install

# Build frontend for production
npm run build

# This creates a 'dist' folder with production-ready files
cd ..
```

### 3.4 Configure Environment Variables

```bash
# Create .env file
nano .env
```

Add your API keys:
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
```

Save and exit (Ctrl+X, then Y, then Enter).

### 3.5 Set Proper Permissions

```bash
# Make sure the application user owns all files
sudo chown -R reputationrecon:reputationrecon /home/reputationrecon/ReputationRecon

# Set proper permissions
chmod 600 .env
chmod +x run_server.sh
```

## Step 4: Configure Nginx Reverse Proxy

### 4.1 Create Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/reputationrecon
```

Add the following configuration (replace `your-domain.com` with your actual domain):

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name your-domain.com www.your-domain.com;
    
    # For Let's Encrypt verification
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    # SSL Configuration (will be updated by certbot)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
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

    # Serve static files from built frontend
    location / {
        root /home/reputationrecon/ReputationRecon/client/dist;
        try_files $uri $uri/ /index.html;
        index index.html;
    }

    # Serve logo.png
    location /logo.png {
        root /home/reputationrecon/ReputationRecon;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Proxy API requests to FastAPI backend
    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Proxy WebSocket connections (if needed)
    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4.2 Enable the Site

```bash
# Create symbolic link
sudo ln -s /etc/nginx/sites-available/reputationrecon /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# If test passes, reload Nginx
sudo systemctl reload nginx
```

## Step 5: Obtain SSL Certificate with Let's Encrypt

### 5.1 Get Certificate

```bash
# Replace your-domain.com with your actual domain
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Follow the prompts:
# - Enter your email address
# - Agree to terms of service
# - Choose whether to redirect HTTP to HTTPS (recommended: Yes)
```

### 5.2 Test Auto-Renewal

```bash
# Test the renewal process
sudo certbot renew --dry-run

# Certbot will auto-renew certificates, but you can verify with:
sudo certbot certificates
```

## Step 6: Configure Systemd Service for Backend

### 6.1 Create Systemd Service File

```bash
sudo nano /etc/systemd/system/reputationrecon.service
```

Add the following:

```ini
[Unit]
Description=ReputationRecon FastAPI Backend
After=network.target

[Service]
Type=simple
User=reputationrecon
Group=reputationrecon
WorkingDirectory=/home/reputationrecon/ReputationRecon
Environment="PATH=/home/reputationrecon/ReputationRecon/venv/bin"
EnvironmentFile=/home/reputationrecon/ReputationRecon/.env
ExecStart=/home/reputationrecon/ReputationRecon/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/reputationrecon/ReputationRecon

[Install]
WantedBy=multi-user.target
```

### 6.2 Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable reputationrecon

# Start the service
sudo systemctl start reputationrecon

# Check status
sudo systemctl status reputationrecon

# View logs
sudo journalctl -u reputationrecon -f
```

## Step 7: Configure Log Rotation

### 7.1 Create Logrotate Configuration

```bash
sudo nano /etc/logrotate.d/reputationrecon
```

Add:

```
/home/reputationrecon/ReputationRecon/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 reputationrecon reputationrecon
    sharedscripts
}
```

## Step 8: Final Configuration

### 8.1 Update Vite Config for Production

Make sure your `client/vite.config.ts` has the correct base path:

```typescript
export default defineConfig({
  plugins: [react()],
  base: '/', // Change this if deploying to a subdirectory
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
  },
  // ... rest of config
})
```

### 8.2 Update API Base URL (if needed)

If your frontend needs to call the API from a different domain, update `client/src/services/api.ts`:

```typescript
// For production, you might want to use relative paths
const API_BASE = '/api'  // This should work with the nginx config above
```

## Step 9: Verify Deployment

### 9.1 Check Services

```bash
# Check backend service
sudo systemctl status reputationrecon

# Check Nginx
sudo systemctl status nginx

# Check SSL certificate
sudo certbot certificates
```

### 9.2 Test the Application

1. Visit `https://your-domain.com` - should show the frontend
2. Visit `https://your-domain.com/api/docs` - should show API documentation
3. Test an assessment to ensure everything works

## Step 10: Maintenance Commands

### Update Application

```bash
# Switch to application user
sudo su - reputationrecon

# Navigate to application directory
cd ReputationRecon

# Pull latest changes
git pull

# Update Python dependencies
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Rebuild frontend
cd client
npm install
npm run build
cd ..

# Restart service
sudo systemctl restart reputationrecon
```

### View Logs

```bash
# Backend logs
sudo journalctl -u reputationrecon -f

# Nginx access logs
sudo tail -f /var/log/nginx/reputationrecon_access.log

# Nginx error logs
sudo tail -f /var/log/nginx/reputationrecon_error.log
```

### Restart Services

```bash
# Restart backend
sudo systemctl restart reputationrecon

# Restart Nginx
sudo systemctl restart nginx

# Reload Nginx (without downtime)
sudo systemctl reload nginx
```

## Troubleshooting

### Backend Not Starting

```bash
# Check service status
sudo systemctl status reputationrecon

# Check logs
sudo journalctl -u reputationrecon -n 50

# Verify environment variables
sudo cat /home/reputationrecon/ReputationRecon/.env

# Test manually
sudo su - reputationrecon
cd ReputationRecon
source venv/bin/activate
python main.py
```

### Nginx Issues

```bash
# Test configuration
sudo nginx -t

# Check error logs
sudo tail -f /var/log/nginx/error.log

# Check if port 80/443 are in use
sudo netstat -tulpn | grep :80
sudo netstat -tulpn | grep :443
```

### SSL Certificate Issues

```bash
# Check certificate status
sudo certbot certificates

# Renew certificate manually
sudo certbot renew

# Check certificate expiration
sudo certbot certificates | grep Expiry
```

### Permission Issues

```bash
# Fix ownership
sudo chown -R reputationrecon:reputationrecon /home/reputationrecon/ReputationRecon

# Fix permissions
sudo chmod 600 /home/reputationrecon/ReputationRecon/.env
```

## Security Recommendations

1. **Keep system updated**: `sudo apt update && sudo apt upgrade -y`
2. **Use strong passwords**: For SSH and database access
3. **Disable root SSH login**: Edit `/etc/ssh/sshd_config` and set `PermitRootLogin no`
4. **Use SSH keys**: Instead of passwords for SSH access
5. **Regular backups**: Backup your database and `.env` file
6. **Monitor logs**: Regularly check application and system logs
7. **Rate limiting**: Already configured in the application, but you can add Nginx rate limiting too
8. **Fail2ban**: Install and configure to prevent brute force attacks

## Backup Strategy

```bash
# Create backup script
sudo nano /usr/local/bin/backup-reputationrecon.sh
```

Add:

```bash
#!/bin/bash
BACKUP_DIR="/home/reputationrecon/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
cp /home/reputationrecon/ReputationRecon/assessments_cache.db $BACKUP_DIR/assessments_cache_$DATE.db

# Backup .env file
cp /home/reputationrecon/ReputationRecon/.env $BACKUP_DIR/env_$DATE

# Keep only last 7 days of backups
find $BACKUP_DIR -type f -mtime +7 -delete
```

Make executable:
```bash
sudo chmod +x /usr/local/bin/backup-reputationrecon.sh
```

Add to crontab:
```bash
sudo crontab -e
# Add: 0 2 * * * /usr/local/bin/backup-reputationrecon.sh
```

## Performance Tuning

### Increase Workers

Edit `/etc/systemd/system/reputationrecon.service` and adjust the `--workers` parameter based on your server's CPU cores:

```ini
ExecStart=/home/reputationrecon/ReputationRecon/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 4
```

Recommended: `workers = (2 × CPU cores) + 1`

### Enable Gzip Compression in Nginx

Add to your nginx config:

```nginx
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/json;
```

## Monitoring

Consider setting up monitoring with:
- **Uptime monitoring**: UptimeRobot, Pingdom
- **Application monitoring**: Sentry, New Relic
- **Server monitoring**: Prometheus + Grafana, Netdata

---

**Your application should now be running at `https://your-domain.com` with full HTTPS encryption!**

