#!/bin/bash

# SSL Troubleshooting Script for ReputationRecon
# Run this script to diagnose SSL certificate issues

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=========================================="
echo "SSL Certificate Troubleshooting"
echo "==========================================${NC}"
echo ""

# Get domain from nginx config
DOMAIN=$(grep -m 1 "server_name" /etc/nginx/sites-available/reputationrecon 2>/dev/null | awk '{print $2}' | sed 's/;//' | head -1)

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Could not detect domain from Nginx config${NC}"
    read -p "Enter your domain: " DOMAIN
fi

echo -e "${YELLOW}Domain: $DOMAIN${NC}"
echo ""

# 1. Check if certificates exist
echo -e "${YELLOW}[1] Checking SSL certificates...${NC}"
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo -e "${GREEN}✓ Certificate file exists${NC}"
    sudo ls -la /etc/letsencrypt/live/$DOMAIN/
    echo ""
    echo "Certificate details:"
    sudo openssl x509 -in /etc/letsencrypt/live/$DOMAIN/fullchain.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After"
else
    echo -e "${RED}✗ Certificate file NOT found at /etc/letsencrypt/live/$DOMAIN/fullchain.pem${NC}"
    echo ""
    echo "Attempting to obtain certificate..."
    read -p "Enter your email for Let's Encrypt: " EMAIL
    sudo certbot certonly --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email $EMAIL
fi
echo ""

# 2. Check certbot certificates
echo -e "${YELLOW}[2] Checking certbot certificate status...${NC}"
sudo certbot certificates
echo ""

# 3. Check Nginx configuration
echo -e "${YELLOW}[3] Checking Nginx configuration...${NC}"
if sudo nginx -t 2>&1 | grep -q "successful"; then
    echo -e "${GREEN}✓ Nginx configuration is valid${NC}"
else
    echo -e "${RED}✗ Nginx configuration has errors:${NC}"
    sudo nginx -t
fi
echo ""

# 4. Check if Nginx is listening on port 443
echo -e "${YELLOW}[4] Checking if Nginx is listening on port 443...${NC}"
if sudo netstat -tuln | grep -q ":443 "; then
    echo -e "${GREEN}✓ Nginx is listening on port 443${NC}"
else
    echo -e "${RED}✗ Nginx is NOT listening on port 443${NC}"
fi
echo ""

# 5. Check Nginx error logs
echo -e "${YELLOW}[5] Recent Nginx SSL errors:${NC}"
sudo tail -20 /var/log/nginx/error.log | grep -i ssl || echo "No SSL errors found in recent logs"
echo ""

# 6. Check current Nginx SSL configuration
echo -e "${YELLOW}[6] Current Nginx SSL configuration:${NC}"
sudo grep -A 5 "ssl_certificate" /etc/nginx/sites-available/reputationrecon || echo "No SSL configuration found"
echo ""

# 7. Test SSL connection
echo -e "${YELLOW}[7] Testing SSL connection...${NC}"
if command -v openssl &> /dev/null; then
    echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>&1 | grep -E "Verify return code|Protocol|Cipher" || echo "Could not connect to SSL"
else
    echo "openssl not available for testing"
fi
echo ""

# 8. Check if certbot modified the config correctly
echo -e "${YELLOW}[8] Checking if certbot properly configured Nginx...${NC}"
if sudo grep -q "managed by Certbot" /etc/nginx/sites-available/reputationrecon; then
    echo -e "${GREEN}✓ Nginx config is managed by Certbot${NC}"
else
    echo -e "${YELLOW}⚠ Nginx config may not be fully managed by Certbot${NC}"
    echo "You may need to run: sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN"
fi
echo ""

# 9. Recommendations
echo -e "${YELLOW}=========================================="
echo "Recommendations:"
echo "==========================================${NC}"

if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo -e "${RED}1. Obtain SSL certificate:${NC}"
    echo "   sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN"
    echo ""
fi

if ! sudo nginx -t 2>&1 | grep -q "successful"; then
    echo -e "${RED}2. Fix Nginx configuration errors above${NC}"
    echo ""
fi

if ! sudo netstat -tuln | grep -q ":443 "; then
    echo -e "${RED}3. Restart Nginx:${NC}"
    echo "   sudo systemctl restart nginx"
    echo ""
fi

echo -e "${YELLOW}4. If issues persist, try:${NC}"
echo "   sudo certbot delete --cert-name $DOMAIN"
echo "   sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email your-email@example.com --redirect"
echo ""

echo -e "${GREEN}Troubleshooting complete!${NC}"

