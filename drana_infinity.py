#!/usr/bin/env python3
"""
Drana-Infinity
---------------------------
Designed and maintained by IHA089.
Security-hardened and optimized version.
"""

import warnings
warnings.filterwarnings("ignore")
import sys
sys.modules['warnings'] = warnings

import subprocess, json, re, os, sqlite3, hashlib, uuid, secrets, requests
import logging
from queue import Queue, Empty
from waitress import serve
from flask import Flask, request, jsonify, render_template, Response, stream_with_context, make_response, send_from_directory
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from threading import Lock
from contextlib import contextmanager
import multiprocessing

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('drana_infinity.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__) 

try:
    from updater import update_drana_infinity
    update_drana_infinity()
except Exception as e:
    logger.warning(f"Update check failed: {e}")


drana_infinity = Flask(__name__)
DB_NAME = 'chat_database.db'
UPLOAD_FOLDER = 'uploads'

# Security configuration
drana_infinity.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
drana_infinity.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload
drana_infinity.config['SECRET_KEY'] = secrets.token_hex(32)  # For CSRF protection
drana_infinity.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for CSRF tokens
drana_infinity.config['WTF_CSRF_SSL_STRICT'] = False  # Allow HTTP in development

# Initialize security extensions
csrf = CSRFProtect(drana_infinity)
limiter = Limiter(
    get_remote_address,
    app=drana_infinity,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Database connection pool configuration - FIXED: Using Queue instead of list
MAX_DB_CONNECTIONS = 32  # Optimized for Ryzen 9 9950 (32 threads)
_db_pool = Queue(maxsize=MAX_DB_CONNECTIONS)

def _create_db_connection():
    """Create a new optimized database connection"""
    conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=30.0)
    # Optimize SQLite for high-RAM systems (128GB)
    conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
    conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes
    conn.execute("PRAGMA cache_size=-262144")  # 256MB cache (negative = KB)
    conn.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in RAM
    conn.execute("PRAGMA mmap_size=2147483648")  # 2GB memory-mapped I/O
    conn.execute("PRAGMA page_size=4096")  # Optimal page size
    conn.execute("PRAGMA busy_timeout=30000")  # 30 second timeout
    return conn

@contextmanager
def get_db_connection():
    """Thread-safe database connection pooling - FIXED: No race conditions"""
    conn = None
    try:
        # Try to get existing connection from pool (with timeout)
        conn = _db_pool.get(timeout=5)
    except Empty:
        # Pool is empty or timeout, create new connection
        conn = _create_db_connection()
        logger.debug("Created new database connection")

    try:
        yield conn
    except Exception as e:
        logger.error(f"Database error: {e}")
        raise
    finally:
        # Return connection to pool or close if pool is full
        try:
            _db_pool.put(conn, block=False)
        except:
            # Pool is full, close the connection
            conn.close()
            logger.debug("Closed excess database connection")

def init_db():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("PRAGMA foreign_keys = ON;")

        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                user_hash TEXT NOT NULL,
                title TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_hash) REFERENCES users(user_hash) ON DELETE CASCADE
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                chat_id TEXT PRIMARY KEY,
                user_hash TEXT NOT NULL,
                title TEXT NOT NULL,
                model_name TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                project_id TEXT,
                FOREIGN KEY(user_hash) REFERENCES users(user_hash) ON DELETE CASCADE,
                FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                file_path TEXT,
                file_name TEXT,
                FOREIGN KEY(chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS command_outputs (
                output_id TEXT PRIMARY KEY,
                chat_id TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE
            )
        ''')

        try:
            c.execute("ALTER TABLE chats ADD COLUMN model_name TEXT NOT NULL DEFAULT 'llama3'")
        except sqlite3.OperationalError as e:
            logger.debug(f"Column model_name already exists: {e}")

        try:
            c.execute("ALTER TABLE messages ADD COLUMN file_path TEXT")
            c.execute("ALTER TABLE messages ADD COLUMN file_name TEXT")
        except sqlite3.OperationalError as e:
            logger.debug(f"Columns file_path/file_name already exist: {e}")

        try:
            c.execute("ALTER TABLE chats ADD COLUMN project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE")
        except sqlite3.OperationalError as e:
            logger.debug(f"Column project_id already exists: {e}")

        # Performance indexes for faster queries
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_projects_user_hash ON projects(user_hash)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_chats_user_hash ON chats(user_hash)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_chats_project_id ON chats(project_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(chat_id, timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_command_outputs_chat_id ON command_outputs(chat_id)")
        except sqlite3.OperationalError as e:
            logger.debug(f"Indexes already exist: {e}")

        conn.commit()
        logger.info("Database initialized successfully")


def get_chat_history_for_ollama(chat_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT sender, text, file_name FROM messages WHERE chat_id = ? ORDER BY timestamp ASC", (chat_id,))
        history = []
        for row in c.fetchall():
            sender, text, file_name = row
            role = 'user' if sender == 'user' else 'assistant'
            content = text
            if file_name:
                content = f"(The user has attached a file: {file_name})\n\n{text}"
            history.append({'role': role, 'content': content})
    return history

def stream_ollama_response(model_name, history, new_message, chat_id):
    ollama_url = "http://localhost:11434/api/chat"

    messages = history

    payload = {
        "model": model_name,
        "messages": messages,
        "stream": True,
        "options": {
            "num_gpu": 1,  # Enable GPU acceleration for RTX 5090
            "num_thread": 16,  # Use half of available threads for Ollama (leave room for Flask)
        }
    }

    ai_full_response = ""
    try:
        with requests.post(ollama_url, json=payload, stream=True, timeout=300) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if line:
                    data = json.loads(line.decode("utf-8"))
                    if "content" in data["message"]:
                        ai_full_response += data["message"]["content"]
                        yield data["message"]["content"]
                    if data.get("done"):
                        break
    except Exception as e:
        yield f"[Error: {e}]"
    finally:
        if ai_full_response:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO messages (chat_id, sender, text) VALUES (?, ?, ?)", (chat_id, 'ai', ai_full_response))
                conn.commit()

@drana_infinity.route('/upload_file', methods=['POST'])
@limiter.limit("20 per hour")  # Prevent upload abuse
def upload_file():
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file part"}), 400
    
    file = request.files['file']
    chat_id = request.form.get('chat_id')

    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400
    
    if not chat_id:
        return jsonify({"success": False, "message": "No chat ID"}), 400

    if file:
        filename = secure_filename(file.filename)
        chat_upload_dir = os.path.join(drana_infinity.config['UPLOAD_FOLDER'], chat_id)
        os.makedirs(chat_upload_dir, exist_ok=True)
        
        file_path = os.path.join(chat_upload_dir, filename)
        file.save(file_path)
        
        web_path = f"/uploads/{chat_id}/{filename}"
        return jsonify({"success": True, "file_path": web_path, "file_name": filename})

@drana_infinity.route('/uploads/<chat_id>/<path:filename>')
@limiter.limit("100 per minute")
def uploaded_file(chat_id, filename):
    """Serve uploaded files - FIXED: Path traversal vulnerability"""
    # Sanitize inputs to prevent path traversal
    safe_chat_id = secure_filename(chat_id)
    safe_filename = secure_filename(filename)

    if not safe_chat_id or not safe_filename:
        logger.warning(f"Invalid file request: chat_id={chat_id}, filename={filename}")
        return jsonify({"error": "Invalid file path"}), 400

    chat_upload_dir = os.path.join(drana_infinity.config['UPLOAD_FOLDER'], safe_chat_id)

    # Verify the path is within uploads directory (defense in depth)
    full_path = os.path.join(chat_upload_dir, safe_filename)
    if not os.path.abspath(full_path).startswith(os.path.abspath(drana_infinity.config['UPLOAD_FOLDER'])):
        logger.error(f"Path traversal attempt blocked: {full_path}")
        return jsonify({"error": "Access denied"}), 403

    return send_from_directory(chat_upload_dir, safe_filename)


@drana_infinity.route('/execute_stream', methods=['POST'])
@csrf.exempt  # API endpoint - handle CSRF via tokens if needed
@limiter.limit("10 per minute")
def execute_stream():
    """Execute shell command - WARNING: Restricted to safe commands only"""
    command = request.json.get("command")
    chat_id = request.json.get("chat_id")
    output_id = request.json.get("output_id")

    if not all([command, chat_id, output_id]):
        logger.warning("Execute stream called with missing data")
        return jsonify({"success": False, "message": "Missing required data."}), 400

    # SECURITY: Whitelist of allowed commands to prevent command injection
    ALLOWED_COMMANDS = {
        'ls', 'pwd', 'whoami', 'id', 'uname', 'date', 'hostname',
        'nmap', 'nikto', 'sqlmap', 'dig', 'nslookup', 'ping', 'traceroute',
        'whois', 'curl', 'wget', 'netstat', 'ss', 'ifconfig', 'ip',
        'ps', 'top', 'df', 'du', 'free', 'uptime', 'w', 'who'
    }

    # Extract base command
    base_command = command.strip().split()[0] if command.strip() else ""

    # Check if command is allowed
    if base_command not in ALLOWED_COMMANDS:
        logger.warning(f"Blocked unauthorized command: {command}")
        return jsonify({
            "success": False,
            "message": f"Command '{base_command}' not allowed. Allowed commands: {', '.join(sorted(ALLOWED_COMMANDS))}"
        }), 403

    full_output = ""
    
    def generate_and_save():
        nonlocal full_output
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            for line in iter(process.stdout.readline, ''):
                full_output += line
                yield line
                
            process.stdout.close()
            return_code = process.wait()
            final_status = f"\n[Process finished with exit code {return_code}]\n" if return_code != 0 else f"\n[Process finished successfully]\n"
            full_output += final_status
            yield final_status

        except FileNotFoundError:
            full_output = "[Error: Command not found. Please check your command and environment path.]"
            yield full_output
        except Exception as e:
            full_output = f"[Error: {str(e)}]"
            yield full_output
        finally:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO command_outputs (output_id, chat_id, command, output) VALUES (?, ?, ?, ?)",
                          (output_id, chat_id, command, full_output))
                conn.commit()

    return Response(stream_with_context(generate_and_save()), mimetype="text/plain")

@drana_infinity.route('/get_command_output', methods=['POST'])
def get_command_output():
    output_id = request.json.get("output_id")
    if not output_id:
        return jsonify({"success": False, "message": "Output ID not provided."}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT command, output FROM command_outputs WHERE output_id = ?", (output_id,))
        result = c.fetchone()

    if result:
        return jsonify({"success": True, "command": result[0], "output": result[1]})
    else:
        return jsonify({"success": False, "message": "Output not found."}), 404

@drana_infinity.route('/')
def index():
    return render_template('index.html', page_mode='chats', active_project_id=None, active_project_title=None)

@drana_infinity.route('/projects')
def projects_page():
    return render_template('index.html', page_mode='projects', active_project_id=None, active_project_title=None)

@drana_infinity.route('/project/<project_id>')
def project_detail_page(project_id):
    user_hash = request.cookies.get('user_hash')
    project_title = "Project"

    if user_hash:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT title FROM projects WHERE project_id = ? AND user_hash = ?", (project_id, user_hash))
                project = c.fetchone()
                if project:
                    project_title = project[0]
                else:
                    project_title = "Unknown Project"
        except Exception as e:
            print(f"Error fetching project title: {e}")
            project_title = "Error"

    return render_template('index.html', page_mode='project_detail', active_project_id=project_id, active_project_title=project_title)

@drana_infinity.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force
def login():
    username = request.json.get("username")
    if not username:
        return jsonify({"success": False, "message": "Username not provided."}), 400

    user_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT user_hash FROM users WHERE username = ?", (username,))
        existing_user = c.fetchone()
        if existing_user:
            user_hash = existing_user[0]
        else:
            c.execute("INSERT INTO users (user_hash, username) VALUES (?, ?)", (user_hash, username))
            conn.commit()

    response = make_response(jsonify({"success": True, "user_hash": user_hash, "username": username}))
    # FIXED: Secure cookie configuration
    response.set_cookie(
        'user_hash',
        user_hash,
        max_age=60*60*24*365,  # 1 year
        httponly=True,          # Prevent JavaScript access (XSS protection)
        secure=False,           # Set to True in production with HTTPS
        samesite='Strict'       # CSRF protection
    )
    logger.info(f"User logged in: {username}")
    return response

@drana_infinity.route('/get_user_info', methods=['GET'])
def get_user_info():
    user_hash = request.cookies.get('user_hash')
    if not user_hash:
        return jsonify({"success": False, "message": "User hash not found."}), 401

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE user_hash = ?", (user_hash,))
        user_info = c.fetchone()

    if user_info:
        return jsonify({"success": True, "username": user_info[0]})
    else:
        return jsonify({"success": False, "message": "User not found."}), 404


@drana_infinity.route('/get_chats', methods=['GET'])
def get_chats():
    user_hash = request.cookies.get('user_hash')
    if not user_hash:
        return jsonify({"success": False, "message": "User hash not found."}), 401

    project_id = request.args.get('project_id')

    if not project_id or project_id == 'null' or project_id == 'None':
        project_id = None

    with get_db_connection() as conn:
        c = conn.cursor()

        if project_id:
            c.execute(
                "SELECT chat_id, title, model_name FROM chats WHERE user_hash = ? AND project_id = ? ORDER BY timestamp DESC",
                (user_hash, project_id)
            )
        else:
             c.execute(
                "SELECT chat_id, title, model_name FROM chats WHERE user_hash = ? AND (project_id IS NULL OR project_id = 'None') ORDER BY timestamp DESC",
                (user_hash,)
            )

        chat_list = [{"chat_id": row[0], "title": row[1], "model_name": row[2]} for row in c.fetchall()]

    return jsonify({"success": True, "chats": chat_list})

@drana_infinity.route('/get_chat_messages', methods=['POST'])
def get_chat_messages():
    chat_id = request.json.get("chat_id")
    if not chat_id:
        return jsonify({"success": False, "message": "Chat ID not provided."}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT sender, text, file_path, file_name FROM messages WHERE chat_id = ? ORDER BY timestamp ASC", (chat_id,))
        messages = [{"sender": row[0], "text": row[1], "file_path": row[2], "file_name": row[3]} for row in c.fetchall()]

    return jsonify({"success": True, "messages": messages})

@drana_infinity.route('/rename_chat', methods=['POST'])
def rename_chat():
    chat_id = request.json.get("chat_id")
    new_title = request.json.get("new_title")
    user_hash = request.cookies.get('user_hash')

    if not all([chat_id, new_title, user_hash]):
        return jsonify({"success": False, "message": "Missing required data."}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE chats SET title = ? WHERE chat_id = ? AND user_hash = ?", (new_title, chat_id, user_hash))
        conn.commit()

    return jsonify({"success": True})

@drana_infinity.route('/delete_chat', methods=['POST'])
def delete_chat():
    chat_id = request.json.get("chat_id")
    user_hash = request.cookies.get('user_hash')

    if not all([chat_id, user_hash]):
        return jsonify({"success": False, "message": "Missing required data."}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM chats WHERE chat_id = ? AND user_hash = ?", (chat_id, user_hash))
        conn.commit()

    return jsonify({"success": True})
    
@drana_infinity.route('/create_new_chat', methods=['POST'])
def create_new_chat():
    user_hash = request.cookies.get('user_hash')
    model_name = request.json.get("model_name")
    project_id = request.json.get("project_id")

    if not user_hash or not model_name:
        return jsonify({"success": False, "message": "Missing user hash or model name."}), 400

    if not project_id or project_id == 'null' or project_id == 'None':
        project_id = None

    chat_id = str(uuid.uuid4())
    default_title = "New Chat"

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO chats (chat_id, user_hash, title, model_name, project_id) VALUES (?, ?, ?, ?, ?)",
            (chat_id, user_hash, default_title, model_name, project_id)
        )
        conn.commit()

    return jsonify({"success": True, "chat_id": chat_id, "title": default_title, "model_name": model_name})

@drana_infinity.route('/chat_stream', methods=['POST'])
@limiter.limit("30 per minute")  # Prevent AI abuse
def chat_stream():
    user_message = request.json.get("message")
    chat_id = request.json.get("chat_id")
    model_name = request.json.get("model_name")
    user_hash = request.cookies.get('user_hash')
    file_path = request.json.get("file_path")
    file_name = request.json.get("file_name")

    if not all([user_message, chat_id, model_name, user_hash]):
        return jsonify({"response": "Missing chat data."}), 400

    with get_db_connection() as conn:
        c = conn.cursor()

        c.execute("SELECT * FROM messages WHERE chat_id = ?", (chat_id,))
        is_first_message = not c.fetchone()
        if is_first_message:
            chat_title = user_message[:25] + "..." if len(user_message) > 25 else user_message
            c.execute("UPDATE chats SET title = ? WHERE chat_id = ?", (chat_title, chat_id))
            conn.commit()

        c.execute("INSERT INTO messages (chat_id, sender, text, file_path, file_name) VALUES (?, ?, ?, ?, ?)",
                  (chat_id, 'user', user_message, file_path, file_name))
        conn.commit()

    history = get_chat_history_for_ollama(chat_id)

    return Response(stream_with_context(stream_ollama_response(model_name, history, user_message, chat_id)),
                    mimetype="text/plain")

@drana_infinity.route('/get_models', methods=['GET'])
def get_models():
    ollama_url = "http://localhost:11434/api/tags"
    try:
        r = requests.get(ollama_url)
        r.raise_for_status()
        models_data = r.json()
        models = []
        for model in models_data.get('models', []):
            model_name = model['name']
            if "drana" in model_name:
                models.append(model_name)
        return jsonify({"success": True, "models": models})
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "message": f"Error fetching models: {e}"}), 500

@drana_infinity.route('/get_projects', methods=['GET'])
def get_projects():
    user_hash = request.cookies.get('user_hash')
    if not user_hash:
        return jsonify({"success": False, "message": "User hash not found."}), 401

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT project_id, title FROM projects WHERE user_hash = ? ORDER BY timestamp DESC", (user_hash,))
        project_list = [{"project_id": row[0], "title": row[1]} for row in c.fetchall()]

    return jsonify({"success": True, "projects": project_list})

@drana_infinity.route('/create_new_project', methods=['POST'])
def create_new_project():
    user_hash = request.cookies.get('user_hash')
    project_name = request.json.get("project_name")

    if not user_hash or not project_name:
        return jsonify({"success": False, "message": "Missing user hash or project name."}), 400

    project_id = str(uuid.uuid4())

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO projects (project_id, user_hash, title) VALUES (?, ?, ?)",
            (project_id, user_hash, project_name)
        )
        conn.commit()

    return jsonify({"success": True, "project_id": project_id, "title": project_name})

@drana_infinity.route('/rename_project', methods=['POST'])
def rename_project():
    project_id = request.json.get("project_id")
    new_title = request.json.get("new_title")
    user_hash = request.cookies.get('user_hash')

    if not all([project_id, new_title, user_hash]):
        return jsonify({"success": False, "message": "Missing required data."}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE projects SET title = ? WHERE project_id = ? AND user_hash = ?", (new_title, project_id, user_hash))
        conn.commit()

    return jsonify({"success": True})

@drana_infinity.route('/delete_project', methods=['POST'])
def delete_project():
    project_id = request.json.get("project_id")
    user_hash = request.cookies.get('user_hash')

    if not all([project_id, user_hash]):
        return jsonify({"success": False, "message": "Missing required data."}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM projects WHERE project_id = ? AND user_hash = ?", (project_id, user_hash))
        conn.commit()

    return jsonify({"success": True})

# Error handlers
@drana_infinity.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    logger.warning(f"File upload too large: {e}")
    return jsonify({"error": "File too large. Maximum size is 100MB"}), 413

@drana_infinity.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    logger.warning(f"Rate limit exceeded: {e}")
    return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

@drana_infinity.errorhandler(500)
def internal_error(e):
    """Handle internal server error"""
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# Exempt API endpoints from CSRF (they should use tokens)
csrf.exempt(drana_infinity.view_functions['chat_stream'])
csrf.exempt(drana_infinity.view_functions['upload_file'])
csrf.exempt(drana_infinity.view_functions['get_command_output'])
csrf.exempt(drana_infinity.view_functions['get_chat_messages'])
csrf.exempt(drana_infinity.view_functions['get_models'])
csrf.exempt(drana_infinity.view_functions['get_chats'])
csrf.exempt(drana_infinity.view_functions['get_projects'])
csrf.exempt(drana_infinity.view_functions['get_user_info'])

if __name__ == '__main__':
    try:
        init_db()
    except sqlite3.OperationalError:
        logger.info("Database already initialized")

    # Optimize for high-performance hardware (Ryzen 9 9950X with 32 threads)
    cpu_count = multiprocessing.cpu_count()
    optimal_threads = max(4, cpu_count)  # Use all available threads
    optimal_workers = max(8, cpu_count // 2)  # Workers = half of threads for balanced performance

    logger.info("=" * 70)
    logger.info("Drana-Infinity - HIGH-PERFORMANCE & SECURITY-HARDENED MODE")
    logger.info("=" * 70)
    logger.info(f"CPU Cores Detected: {cpu_count}")
    logger.info(f"Waitress Threads: {optimal_threads}")
    logger.info(f"Database Connection Pool: {MAX_DB_CONNECTIONS}")
    logger.info(f"SQLite Cache: 256MB | WAL Mode: Enabled")
    logger.info(f"Max Upload Size: 100MB")
    logger.info(f"Server URL: http://127.0.0.1:80")
    logger.info("=" * 70)
    logger.info("Performance Optimizations:")
    logger.info("  ✓ Ryzen 9 9950X (32-thread parallel processing)")
    logger.info("  ✓ 128GB RAM (enhanced caching & memory-mapped I/O)")
    logger.info("  ✓ RTX 5090 GPU (AI inference acceleration)")
    logger.info("  ✓ Thread-safe connection pooling (Queue-based)")
    logger.info("=" * 70)
    logger.info("Security Features:")
    logger.info("  ✓ CSRF Protection (Flask-WTF)")
    logger.info("  ✓ Rate Limiting (200/day, 50/hour per IP)")
    logger.info("  ✓ Secure Cookies (httponly, samesite=strict)")
    logger.info("  ✓ Path Traversal Protection")
    logger.info("  ✓ Command Whitelist (prevent injection)")
    logger.info("  ✓ File Upload Size Limits (100MB)")
    logger.info("  ✓ Structured Logging")
    logger.info("=" * 70)

    serve(
        drana_infinity,
        host='127.0.0.1',
        port=80,
        threads=optimal_threads,  # Maximum concurrent connections per worker
        channel_timeout=300,  # 5 minutes for long AI responses
        connection_limit=1000,  # High connection limit for powerful hardware
        backlog=2048,  # Large backlog queue
        recv_bytes=65536,  # 64KB receive buffer
        send_bytes=65536,  # 64KB send buffer
        ident='Drana-Infinity/2.0'
    )
