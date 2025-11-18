# ⚙️ Configuration Guide - Drana-Infinity

Complete configuration guide for Drana-Infinity v2.0 Enhanced Security Edition.

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Environment Variables](#environment-variables)
3. [Flask Configuration](#flask-configuration)
4. [Security Configuration](#security-configuration)
5. [Rate Limiting](#rate-limiting)
6. [File Uploads](#file-uploads)
7. [Database Configuration](#database-configuration)
8. [Logging Configuration](#logging-configuration)
9. [Production Deployment](#production-deployment)
10. [Troubleshooting](#troubleshooting)

---

## 🚀 Quick Start

### 1. Copy Environment Template

```bash
cp .env.example .env
```

### 2. Generate Secret Key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output and update `SECRET_KEY` in `.env`

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python3 drana_infinity.py
```

---

## 🔧 Environment Variables

### Flask Configuration

#### SECRET_KEY ⚠️ **REQUIRED**

**Description**: Secret key for session encryption and CSRF protection

**Default**: Auto-generated (insecure for production)

**Example**:
```env
SECRET_KEY=a7f8d9e6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8
```

**Production**: MUST set manually with strong random value

---

#### FLASK_ENV

**Description**: Flask environment mode

**Options**: `production`, `development`

**Default**: `production`

**Example**:
```env
FLASK_ENV=production
```

---

#### DEBUG

**Description**: Enable Flask debug mode

**Options**: `True`, `False`

**Default**: `False`

**Warning**: NEVER enable in production

**Example**:
```env
DEBUG=False
```

---

### Server Configuration

#### HOST

**Description**: Server bind address

**Default**: `127.0.0.1` (localhost only)

**Production**: Keep as `127.0.0.1` if using reverse proxy

**Example**:
```env
HOST=127.0.0.1
```

---

#### PORT

**Description**: Server port

**Default**: `80`

**Production**: Use `8000` or higher and proxy through nginx

**Example**:
```env
PORT=8000
```

---

#### USE_HTTPS

**Description**: Enable HTTPS mode (future enhancement)

**Options**: `True`, `False`

**Default**: `False`

**Example**:
```env
USE_HTTPS=False
```

---

### Database Configuration

#### DATABASE_NAME

**Description**: SQLite database filename

**Default**: `chat_database.db`

**Example**:
```env
DATABASE_NAME=chat_database.db
```

---

### Upload Configuration

#### UPLOAD_FOLDER

**Description**: Directory for uploaded files

**Default**: `uploads`

**Example**:
```env
UPLOAD_FOLDER=uploads
```

---

#### MAX_FILE_SIZE

**Description**: Maximum file size in bytes

**Default**: `10485760` (10MB)

**Example**:
```env
MAX_FILE_SIZE=10485760
```

**Recommendations**:
- Development: 10MB
- Production: 5-20MB depending on use case

---

#### ALLOWED_EXTENSIONS

**Description**: Comma-separated list of allowed file extensions

**Default**: `txt,pdf,png,jpg,jpeg,gif,csv,json,xml,log,md,py,js,html,css`

**Example**:
```env
ALLOWED_EXTENSIONS=txt,pdf,png,jpg,jpeg,gif,csv,json,xml,log,md
```

**Security Note**: Be restrictive with allowed extensions

---

### Ollama Configuration

#### OLLAMA_URL

**Description**: Ollama API endpoint URL

**Default**: `http://localhost:11434`

**Example**:
```env
OLLAMA_URL=http://localhost:11434
```

---

### Security Configuration

#### SESSION_COOKIE_SECURE

**Description**: Require HTTPS for session cookies

**Options**: `True`, `False`

**Default**: `True`

**Production**: MUST be `True` with HTTPS

**Example**:
```env
SESSION_COOKIE_SECURE=True
```

---

#### SESSION_COOKIE_HTTPONLY

**Description**: Prevent JavaScript access to cookies

**Options**: `True`, `False`

**Default**: `True`

**Recommendation**: Always `True`

**Example**:
```env
SESSION_COOKIE_HTTPONLY=True
```

---

#### SESSION_COOKIE_SAMESITE

**Description**: SameSite cookie attribute

**Options**: `Lax`, `Strict`, `None`

**Default**: `Lax`

**Example**:
```env
SESSION_COOKIE_SAMESITE=Lax
```

**Recommendations**:
- `Lax`: Balanced protection (recommended)
- `Strict`: Maximum protection (may break some flows)
- `None`: Only with `SECURE=True` and valid reason

---

#### PERMANENT_SESSION_LIFETIME

**Description**: Session timeout in seconds

**Default**: `3600` (1 hour)

**Example**:
```env
PERMANENT_SESSION_LIFETIME=3600
```

**Recommendations**:
- High security: 1800 (30 minutes)
- Balanced: 3600 (1 hour)
- Convenience: 86400 (24 hours)

---

### Rate Limiting Configuration

#### RATELIMIT_ENABLED

**Description**: Enable rate limiting

**Options**: `True`, `False`

**Default**: `True`

**Recommendation**: Always `True` in production

**Example**:
```env
RATELIMIT_ENABLED=True
```

---

#### RATELIMIT_STORAGE_URL

**Description**: Storage backend for rate limit data

**Options**:
- `memory://` (development)
- `redis://localhost:6379` (production)

**Default**: `memory://`

**Example**:
```env
# Development
RATELIMIT_STORAGE_URL=memory://

# Production
RATELIMIT_STORAGE_URL=redis://localhost:6379
```

---

#### RATELIMIT_DEFAULT

**Description**: Default rate limits

**Format**: `X per TIME;Y per TIME`

**Default**: `200 per day;50 per hour`

**Example**:
```env
RATELIMIT_DEFAULT=200 per day;50 per hour
```

**Time Units**: `second`, `minute`, `hour`, `day`

---

#### RATELIMIT_UPLOAD

**Description**: Upload endpoint rate limit

**Default**: `10 per hour`

**Example**:
```env
RATELIMIT_UPLOAD=10 per hour
```

---

#### RATELIMIT_COMMAND

**Description**: Command execution rate limit

**Default**: `30 per hour`

**Example**:
```env
RATELIMIT_COMMAND=30 per hour
```

---

### Logging Configuration

#### LOG_LEVEL

**Description**: Logging verbosity level

**Options**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

**Default**: `INFO`

**Example**:
```env
# Development
LOG_LEVEL=DEBUG

# Production
LOG_LEVEL=INFO
```

---

#### LOG_FILE

**Description**: Log file path

**Default**: `drana_infinity.log`

**Example**:
```env
LOG_FILE=drana_infinity.log
```

---

## 🏭 Production Deployment

### Complete Production .env Example

```env
# Flask Configuration
SECRET_KEY=<GENERATE-STRONG-RANDOM-KEY>
FLASK_ENV=production
DEBUG=False

# Server Configuration
HOST=127.0.0.1
PORT=8000
USE_HTTPS=False

# Database
DATABASE_NAME=chat_database.db

# Upload Configuration
UPLOAD_FOLDER=uploads
MAX_FILE_SIZE=10485760
ALLOWED_EXTENSIONS=txt,pdf,png,jpg,jpeg,gif,csv,json,xml,log,md

# Ollama Configuration
OLLAMA_URL=http://localhost:11434

# Security Configuration
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600

# Rate Limiting
RATELIMIT_ENABLED=True
RATELIMIT_STORAGE_URL=redis://localhost:6379
RATELIMIT_DEFAULT=200 per day;50 per hour
RATELIMIT_UPLOAD=10 per hour
RATELIMIT_COMMAND=30 per hour

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/drana_infinity/app.log
```

---

### Nginx Reverse Proxy Configuration

Create `/etc/nginx/sites-available/drana-infinity`:

```nginx
upstream drana_backend {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Client body size limit (match MAX_FILE_SIZE)
    client_max_body_size 10M;

    # Logging
    access_log /var/log/nginx/drana_access.log;
    error_log /var/log/nginx/drana_error.log;

    location / {
        proxy_pass http://drana_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts for streaming
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # Static files (optional optimization)
    location /static/ {
        alias /path/to/drana-infinity/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/drana-infinity /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

### Systemd Service Configuration

Create `/etc/systemd/system/drana-infinity.service`:

```ini
[Unit]
Description=Drana-Infinity AI Assistant
After=network.target

[Service]
Type=simple
User=drana
Group=drana
WorkingDirectory=/home/drana/drana-infinity
Environment="PATH=/home/drana/drana-infinity/venv/bin"
ExecStart=/home/drana/drana-infinity/venv/bin/python3 drana_infinity.py
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/drana/drana-infinity/uploads /home/drana/drana-infinity/chat_database.db

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable drana-infinity
sudo systemctl start drana-infinity
sudo systemctl status drana-infinity
```

---

## 🐛 Troubleshooting

### Issue: "SECRET_KEY not set" warning

**Solution**: Set `SECRET_KEY` in `.env` file

```bash
python3 -c "import secrets; print(secrets.token_hex(32))" > temp_key.txt
```

---

### Issue: Rate limit errors

**Solution**: Adjust rate limits in `.env` or use Redis

```env
RATELIMIT_DEFAULT=500 per day;100 per hour
```

---

### Issue: File upload fails

**Check**:
1. `MAX_FILE_SIZE` is sufficient
2. File extension in `ALLOWED_EXTENSIONS`
3. `uploads/` directory permissions

```bash
chmod 755 uploads/
```

---

### Issue: Cannot connect to Ollama

**Check**:
1. Ollama is running: `ollama serve`
2. `OLLAMA_URL` is correct
3. Firewall allows connection

---

### Issue: Session expires too quickly

**Solution**: Increase `PERMANENT_SESSION_LIFETIME`

```env
PERMANENT_SESSION_LIFETIME=7200  # 2 hours
```

---

### Issue: Logs not writing

**Check**:
1. Log directory exists and writable
2. `LOG_FILE` path is correct
3. Permissions

```bash
mkdir -p /var/log/drana_infinity
chown drana:drana /var/log/drana_infinity
```

---

## 📊 Performance Tuning

### For High Traffic

```env
# Increase rate limits
RATELIMIT_DEFAULT=1000 per day;200 per hour

# Use Redis
RATELIMIT_STORAGE_URL=redis://localhost:6379

# Increase file size if needed
MAX_FILE_SIZE=20971520  # 20MB
```

### For Low Resources

```env
# Decrease limits
MAX_FILE_SIZE=5242880  # 5MB

# Strict rate limits
RATELIMIT_DEFAULT=50 per day;20 per hour
```

---

## 🔗 Related Documentation

- [SECURITY.md](SECURITY.md) - Security features and best practices
- [README.md](README.md) - Installation and basic usage
- `.env.example` - Configuration template

---

**Last Updated**: 2025-01-18
**Version**: 2.0.0 (Enhanced Security Edition)
**Maintained by**: IHA089
