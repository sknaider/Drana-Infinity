# Changelog

All notable changes to Drana-Infinity will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2025-01-18

### 🎉 Major Release - Enhanced Security Edition

This is a major security-focused release that transforms Drana-Infinity into a production-ready application with enterprise-grade security features.

### ✨ Added

#### Security Features
- **Command Injection Prevention**: Removed dangerous `shell=True`, implemented `shlex.split()` for safe command parsing
- **XSS Protection**: Server-side sanitization with `bleach`, client-side protection with `DOMPurify`
- **CSRF Protection**: Flask-WTF CSRF tokens on all state-changing endpoints
- **Rate Limiting**: Flask-Limiter integration with configurable limits per endpoint
- **SQL Injection Prevention**: Comprehensive use of parameterized queries
- **Input Validation**: Length limits, type checking, and pattern validation on all inputs
- **Authorization Controls**: User ownership verification on all resources (chats, projects, files, commands)
- **Secure File Uploads**: Extension whitelist, size limits, UUID-based directory isolation
- **Command Validation**: Pattern-based blocking of dangerous command patterns

#### Logging & Monitoring
- Comprehensive logging system with configurable levels
- Security event tracking (failed logins, blocked commands, rate limits)
- File and console output handlers
- Structured log format with timestamps

#### Configuration Management
- Environment variable support via `python-dotenv`
- `.env.example` template file
- Configurable security settings
- Session management configuration
- Rate limiting configuration

#### Documentation
- **SECURITY.md**: Complete security feature documentation
- **CONFIG.md**: Detailed configuration guide with examples
- **CHANGELOG.md**: Version history tracking
- Updated README.md with v2.0 features

#### Error Handling
- Centralized error handlers for all HTTP error codes
- Graceful error messages
- Proper logging of errors
- User-friendly error responses

### 🔧 Changed

#### Backend (`drana_infinity.py`)
- **BREAKING**: Now requires `.env` configuration file
- Complete rewrite with security-first approach
- Added comprehensive docstrings
- Improved code organization with utility functions section
- Enhanced database initialization with migration support
- Added timeout protection for command execution (60s)
- Improved error handling throughout
- Added user tracking (created_at, last_login timestamps)

#### Dependencies (`requirements.txt`)
- Added `Flask-Limiter==3.5.0` for rate limiting
- Added `Flask-WTF==1.2.1` for CSRF protection
- Added `bcrypt==4.1.2` for password hashing (future use)
- Added `bleach==6.1.0` for HTML sanitization
- Added `python-dotenv==1.0.0` for environment variables
- Added `python-magic==0.4.27` for file type validation
- Added `email-validator==2.1.0` for validation
- Removed duplicate `waitress` entry
- Added version pinning to `GitPython==3.1.40`

#### Configuration
- All hardcoded values moved to environment variables
- SECRET_KEY generation if not provided (with warning)
- Configurable upload limits
- Configurable rate limits
- Configurable session timeout
- Configurable allowed file extensions

### 🐛 Fixed

#### JavaScript (`static/js/script.js`)
- Fixed incorrect button ID in `confirmDeleteProjectBtn` (line 58)
- Changed from `confirm-delete-btn` to `confirm-delete-project-btn`

#### CSS (`static/css/style.css`)
- Fixed typo in border-radius (line 108)
- Changed from `4-px` to `4px`

#### Security Vulnerabilities
- **CRITICAL**: Fixed command injection vulnerability by removing `shell=True`
- **HIGH**: Fixed potential XSS by adding server-side sanitization
- **MEDIUM**: Fixed missing authentication checks on several endpoints
- **MEDIUM**: Fixed path traversal risks in file upload
- **LOW**: Fixed potential SQL injection through better validation

### 🔒 Security

#### Dangerous Patterns Blocked
The following command patterns are now automatically blocked:
- `; rm -rf`
- `| nc`
- `&& rm -rf`
- `> /dev/sd`
- `| bash`
- `| sh`
- Backticks `` ` ` ``
- Command substitution `$(...)`

#### Session Security
- HttpOnly cookies (prevent JavaScript access)
- Secure cookie flag (HTTPS only)
- SameSite protection (Lax mode)
- Configurable session timeout (default 1 hour)

#### Rate Limits
- Login: 10 per minute
- Chat messages: 30 per hour
- File uploads: 10 per hour
- Command execution: 30 per hour
- Default global: 200 per day / 50 per hour

### 📦 Dependencies

#### New Runtime Dependencies
```
Flask-Limiter>=3.5.0
Flask-WTF>=1.2.1
bcrypt>=4.1.2
bleach>=6.1.0
python-dotenv>=1.0.0
python-magic>=0.4.27
email-validator>=2.1.0
```

#### Updated
```
GitPython (now pinned to 3.1.40)
```

### 🗃️ Database Changes

#### Users Table
- Added `password_hash` column (TEXT, nullable)
- Added `created_at` column (DATETIME)
- Added `last_login` column (DATETIME)
- Added UNIQUE constraint on `username`

**Migration**: Automatic via `ALTER TABLE` in `init_db()` - backward compatible

### ⚠️ Breaking Changes

1. **Environment Configuration Required**
   - Application now requires `.env` file or environment variables
   - At minimum, `SECRET_KEY` should be set in production
   - See `.env.example` for template

2. **Command Execution Changes**
   - Some complex shell commands may not work due to `shell=False`
   - Pipe operations and shell features need explicit handling
   - More secure but less flexible

3. **File Upload Restrictions**
   - Default 10MB size limit (configurable)
   - Only whitelisted extensions allowed
   - May reject previously accepted files

4. **Rate Limiting**
   - API calls now rate-limited by default
   - May affect high-frequency usage
   - Configurable per deployment

### 📝 Migration Guide

#### From v1.x to v2.0

1. **Create configuration file**:
   ```bash
   cp .env.example .env
   python3 -c "import secrets; print(secrets.token_hex(32))"
   # Paste output into .env as SECRET_KEY
   ```

2. **Install new dependencies**:
   ```bash
   pip install --upgrade -r requirements.txt
   ```

3. **Test in development**:
   ```bash
   # Set DEBUG=True in .env for testing
   python3 drana_infinity.py
   ```

4. **Review rate limits**:
   - Adjust in `.env` if default limits are too restrictive
   - Consider Redis for production rate limiting

5. **Update command usage**:
   - Test command execution functionality
   - Some complex shell commands may need adjustment

### 🎯 Upgrade Recommendations

#### For Development
```env
DEBUG=True
LOG_LEVEL=DEBUG
RATELIMIT_ENABLED=False
```

#### For Production
```env
DEBUG=False
LOG_LEVEL=INFO
SECRET_KEY=<strong-random-key>
SESSION_COOKIE_SECURE=True
RATELIMIT_ENABLED=True
RATELIMIT_STORAGE_URL=redis://localhost:6379
```

### 📚 Documentation

- Added comprehensive security documentation
- Added detailed configuration guide
- Updated README with v2.0 features
- Added inline code documentation
- Added deployment examples (nginx, systemd)

---

## [1.0.0] - 2024-XX-XX

### Initial Release

#### Features
- Flask-based web application
- Ollama AI model integration
- Chat interface with message history
- Command execution capability
- File upload support
- Project organization system
- SQLite database backend
- Responsive web UI
- Auto-update functionality

#### Components
- `drana_infinity.py` - Main application
- `updater.py` - Auto-update system
- `templates/index.html` - Web interface
- `static/js/script.js` - Frontend logic
- `static/css/style.css` - Styling

---

## Version Numbering

- **Major version (X.0.0)**: Breaking changes, major rewrites
- **Minor version (0.X.0)**: New features, non-breaking changes
- **Patch version (0.0.X)**: Bug fixes, security patches

---

## Links

- [Repository](https://github.com/IHA089/drana-infinity)
- [Security Policy](SECURITY.md)
- [Configuration Guide](CONFIG.md)
- [Issues](https://github.com/IHA089/drana-infinity/issues)

---

**Maintained by IHA089**
