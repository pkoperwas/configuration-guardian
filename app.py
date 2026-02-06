import os
import json
import hashlib
import subprocess
import datetime
import threading
import time
import logging
import shutil
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from pathlib import Path
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Random secret key for sessions

BASE_DIR = "/opt/configuration-guardian"
INV_FILE = f"{BASE_DIR}/config/inventory.json"
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB - limit for backup and preview
STORAGE = f"{BASE_DIR}/data/storage"
INDEX = f"{BASE_DIR}/data/index"
CONFIG_FILE = f"{BASE_DIR}/config/settings.json"
AUTH_FILE = f"{BASE_DIR}/config/htpasswd"
SSH_KEY_FILE = f"{BASE_DIR}/config/ssh_private_key"
LOG_DIR = f"{BASE_DIR}/logs"
ACTIVITY_LOG = f"{LOG_DIR}/activity.log"
SYNC_LOG = f"{LOG_DIR}/sync.log"

# Ensure directories exist
os.makedirs(f"{BASE_DIR}/config", exist_ok=True)
os.makedirs(STORAGE, exist_ok=True)
os.makedirs(INDEX, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(ACTIVITY_LOG),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Separate sync logger
sync_logger = logging.getLogger('sync')
sync_handler = logging.FileHandler(SYNC_LOG)
sync_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
sync_logger.addHandler(sync_handler)
sync_logger.setLevel(logging.INFO)

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def check_auth(username, password):
    """Check htpasswd file for authentication"""
    if not os.path.exists(AUTH_FILE):
        # Create default admin:admin (hashed) if file doesn't exist
        with open(AUTH_FILE, 'w') as f:
            # Format: username:hashed_password
            f.write(f"admin:{hash_password('admin')}\n")
        logger.info("Created default htpasswd file with admin:admin")
    
    try:
        with open(AUTH_FILE, 'r') as f:
            for line in f:
                stored_user, stored_hash = line.strip().split(':', 1)
                if stored_user == username and stored_hash == hash_password(password):
                    return True
    except Exception as e:
        logger.error(f"ERROR: Auth check failed: {str(e)}")
    return False

def get_inventory():
    if not os.path.exists(INV_FILE): 
        return {}
    with open(INV_FILE, 'r') as f: 
        return json.load(f)

def save_inventory(inv):
    with open(INV_FILE, 'w') as f: 
        json.dump(inv, f, indent=4)

def get_settings():
    if not os.path.exists(CONFIG_FILE):
        return {"sync_hour": "02:00", "auto_sync": False}
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_settings(settings):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(settings, f, indent=4)

def run_ssh(srv, remote_cmd):
    # Build SSH command with key if available
    ssh_cmd_parts = ['ssh', '-q']
    
    if os.path.exists(SSH_KEY_FILE):
        ssh_cmd_parts.extend(['-i', SSH_KEY_FILE])
    
    ssh_cmd_parts.extend([
        '-p', str(srv['port']),
        '-o', 'ConnectTimeout=5',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        f"{srv['user']}@{srv['ip']}",
        remote_cmd
    ])
    
    try:
        result = subprocess.check_output(ssh_cmd_parts, stderr=subprocess.PIPE)
        return result.decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else 'Unknown error'
        logger.error(f"SSH command failed: {error_msg}")
        raise Exception(f"SSH command failed: {error_msg}")

def get_file_hash(srv, path):
    """Get remote file's hash to detect changes"""
    try:
        # Use md5sum on remote file with sudo
        escaped_path = path.replace("'", "'\\''")
        result = run_ssh(srv, f"sudo md5sum '{escaped_path}' 2>/dev/null || echo 'ERROR'")
        if 'ERROR' in result:
            return None
        return result.split()[0]
    except:
        return None

def get_file_metadata(srv, path):
    """Get file permissions, owner, and SELinux context"""
    try:
        # Get permissions, owner, group with sudo
        escaped_path = path.replace("'", "'\\''")
        stat_result = run_ssh(srv, f"sudo stat -c '%a:%U:%G' '{escaped_path}' 2>/dev/null || echo 'ERROR'")
        if 'ERROR' in stat_result:
            return None
        
        perms, owner, group = stat_result.strip().split(':')
        
        # Get SELinux context if available
        selinux_ctx = None
        try:
            ctx_result = run_ssh(srv, f"sudo ls -Z '{escaped_path}' 2>/dev/null | awk '{{print $1}}'")
            if ctx_result and not ctx_result.startswith('?') and len(ctx_result.strip()) > 0:
                selinux_ctx = ctx_result.strip()
        except:
            pass
        
        return {
            'permissions': perms,
            'owner': owner,
            'group': group,
            'selinux_context': selinux_ctx
        }
    except:
        return None

def backup_file(srv, remote_path):
    """Backup a single file using compression - no deduplication, files stored per server"""
    srv_idx_dir = os.path.join(INDEX, srv['ip'])
    srv_storage_dir = os.path.join(STORAGE, srv['ip'])
    os.makedirs(srv_idx_dir, exist_ok=True)
    os.makedirs(srv_storage_dir, exist_ok=True)
    
    sync_logger.info(f"Starting backup for {srv['hostname']}:{remote_path}")
    
    # Enforce 1MB size limit (same as preview and UI)
    escaped_path = remote_path.replace("'", "'\\''")
    try:
        size_result = run_ssh(srv, f"sudo stat -c '%s' '{escaped_path}' 2>/dev/null || echo '0'")
        size = int(size_result.strip())
    except (ValueError, Exception):
        size = 0
    if size > MAX_FILE_SIZE_BYTES:
        sync_logger.warning(f"Skipping {remote_path}: exceeds 1MB limit ({size} bytes)")
        return {"status": "error", "message": f"File exceeds 1MB size limit ({size / 1024 / 1024:.2f} MB)"}
    
    # Get file hash and metadata
    file_hash = get_file_hash(srv, remote_path)
    if not file_hash:
        sync_logger.error(f"ERROR: Cannot read file or calculate hash for {remote_path}")
        return {"status": "error", "message": "Cannot read file or calculate hash"}
    
    metadata = get_file_metadata(srv, remote_path)
    if not metadata:
        sync_logger.error(f"ERROR: Cannot read file metadata for {remote_path}")
        return {"status": "error", "message": "Cannot read file metadata"}
    
    # Check if we already have this version
    index_file = os.path.join(srv_idx_dir, f"{hashlib.md5(remote_path.encode()).hexdigest()}.json")
    if os.path.exists(index_file):
        with open(index_file, 'r') as f:
            history = json.load(f)
            if history and history[-1].get('hash') == file_hash:
                sync_logger.info(f"File unchanged, skipping: {remote_path}")
                return {"status": "unchanged", "message": "File unchanged, skipping backup"}
    else:
        history = []
    
    # Backup the file - always create new file with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Store in server-specific directory with unique timestamp
    storage_file = os.path.join(srv_storage_dir, f"{hashlib.md5(remote_path.encode()).hexdigest()}_{timestamp}.gz")
    
    # Always download - no deduplication
    # Check if SSH key exists
    ssh_key_option = ""
    if os.path.exists(SSH_KEY_FILE):
        ssh_key_option = f"-i {SSH_KEY_FILE}"
    
    backup_cmd = f"ssh -q {ssh_key_option} -p {str(srv.get('port', 22))} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR {srv['user']}@{srv['ip']} 'sudo cat {escaped_path}' | gzip > {storage_file}"
    try:
        sync_logger.info(f"Downloading and compressing: {remote_path}")
        subprocess.run(backup_cmd, shell=True, check=True, stderr=subprocess.DEVNULL)
        sync_logger.info(f"Successfully backed up: {remote_path} -> {storage_file} ({os.path.getsize(storage_file)} bytes)")
    except subprocess.CalledProcessError:
        sync_logger.error(f"ERROR: Backup transfer failed for {remote_path}")
        return {"status": "error", "message": "Backup transfer failed"}
    
    # Update index with metadata
    history.append({
        "date": timestamp,
        "hash": file_hash,
        "path": remote_path,
        "size": os.path.getsize(storage_file),
        "storage_file": storage_file,  # Store actual file path
        "permissions": metadata['permissions'],
        "owner": metadata['owner'],
        "group": metadata['group'],
        "selinux_context": metadata['selinux_context']
    })
    
    with open(index_file, 'w') as f:
        json.dump(history, f, indent=4)
    
    sync_logger.info(f"Backup complete: {remote_path}")
    return {"status": "success", "message": f"Backed up: {remote_path}", "hash": file_hash}

def sync_all_servers():
    """Sync all configured paths for all servers"""
    inv = get_inventory()
    results = {"total": 0, "success": 0, "unchanged": 0, "errors": 0, "details": []}
    
    sync_logger.info("=" * 80)
    
    for ip, srv in inv.items():
        sync_logger.info(f"Processing server: {srv['hostname']} ({ip})")
        for path in srv.get('paths', []):
            results['total'] += 1
            try:
                result = backup_file(srv, path)
                if result['status'] == 'success':
                    results['success'] += 1
                elif result['status'] == 'unchanged':
                    results['unchanged'] += 1
                results['details'].append(f"[{srv['hostname']}] {path}: {result['message']}")
            except Exception as e:
                results['errors'] += 1
                error_msg = f"[{srv['hostname']}] {path}: ERROR - {str(e)}"
                results['details'].append(error_msg)
                sync_logger.error(f"ERROR: {error_msg}")
    
    sync_logger.info("=" * 80)
    sync_logger.info(f"SYNC COMPLETE - Success: {results['success']}, Unchanged: {results['unchanged']}, Errors: {results['errors']}")
    sync_logger.info("=" * 80)
    
    return results

# Background scheduler
def scheduler_thread():
    """Background thread for automatic sync"""
    while True:
        settings = get_settings()
        if settings.get('auto_sync', False):
            current_time = datetime.datetime.now().strftime("%H:%M")
            target_time = settings.get('sync_hour', '02:00')
            
            if current_time == target_time:
                sync_logger.info(f"SYNC STARTED via scheduled activity at {current_time}")
                sync_all_servers()
                time.sleep(60)  # Sleep for a minute to avoid multiple triggers
        
        time.sleep(30)  # Check every 30 seconds

# Start scheduler in background
scheduler = threading.Thread(target=scheduler_thread, daemon=True)
scheduler.start()

@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('login.html')
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if check_auth(username, password):
        session['logged_in'] = True
        session['username'] = username
        logger.info(f"User {username} logged in successfully")
        return jsonify({"status": "success"})
    
    logger.warning(f"ERROR: Failed login attempt for user {username}")
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return jsonify({"status": "success"})

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    username = session.get('username')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not all([current_password, new_password]):
        return jsonify({"status": "error", "message": "All fields required"}), 400
    
    # Verify current password
    if not check_auth(username, current_password):
        logger.warning(f"ERROR: Failed password change attempt for {username} - wrong current password")
        return jsonify({"status": "error", "message": "Current password incorrect"}), 401
    
    # Update password
    try:
        lines = []
        updated = False
        with open(AUTH_FILE, 'r') as f:
            for line in f:
                stored_user, _ = line.strip().split(':', 1)
                if stored_user == username:
                    lines.append(f"{username}:{hash_password(new_password)}\n")
                    updated = True
                else:
                    lines.append(line)
        
        if updated:
            with open(AUTH_FILE, 'w') as f:
                f.writelines(lines)
            logger.info(f"Password changed for user {username}")
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "User not found"}), 404
    except Exception as e:
        logger.error(f"ERROR: Password change failed: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to change password"}), 500

@app.route('/api/servers', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def servers():
    inv = get_inventory()
    
    if request.method == 'DELETE':
        ip = request.json.get('ip')
        if ip in inv:
            hostname = inv[ip]['hostname']
            
            # Clean up all backups for this server
            cleanup_server_backups(ip)
            
            del inv[ip]
            save_inventory(inv)
            logger.info(f"User {session.get('username')} deleted server: {hostname} ({ip})")
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Server not found"}), 404
    
    if request.method in ['POST', 'PUT']:
        data = request.json
        ip = data['ip']
        hostname = data['hostname']
        new_paths = set(data.get('paths', []))
        
        # Check for duplicates (allow updates to same IP)
        for existing_ip, srv in inv.items():
            if existing_ip != ip:  # Only check other servers
                if srv['hostname'] == hostname:
                    logger.warning(f"ERROR: User {session.get('username')} attempted duplicate hostname: {hostname}")
                    return jsonify({"status": "error", "message": f"Hostname '{hostname}' already exists"}), 400
            if existing_ip == ip and request.method == 'POST':
                # For POST (new server), IP must be unique
                logger.warning(f"ERROR: User {session.get('username')} attempted duplicate IP: {ip}")
                return jsonify({"status": "error", "message": f"Server with IP {ip} already exists. Use edit instead."}), 400
        
        # For PUT (edit), check if any paths were removed and clean them up
        if request.method == 'PUT' and ip in inv:
            old_paths = set(inv[ip].get('paths', []))
            removed_paths = old_paths - new_paths
            
            if removed_paths:
                cleanup_removed_paths(ip, removed_paths)
                logger.info(f"Cleaned up {len(removed_paths)} removed backup paths for {ip}")
        
        inv[ip] = {
            'hostname': hostname,
            'user': data.get('user', 'root'),
            'port': data.get('port', '22'),
            'paths': list(new_paths),
            'ip': ip
        }
        save_inventory(inv)
        action = 'updated' if request.method == 'PUT' else 'added'
        logger.info(f"User {session.get('username')} {action} server: {hostname} ({ip})")
        return jsonify({"status": "success"})
    
    return jsonify(inv)

def cleanup_server_backups(ip):
    """Clean up all backup files and indexes for a server"""
    srv_idx_dir = os.path.join(INDEX, ip)
    if os.path.exists(srv_idx_dir):
        shutil.rmtree(srv_idx_dir)
        logger.info(f"Removed index directory for {ip}")
    
    srv_storage_dir = os.path.join(STORAGE, ip)
    if os.path.exists(srv_storage_dir):
        shutil.rmtree(srv_storage_dir)
        logger.info(f"Removed storage directory for {ip}")

def cleanup_removed_paths(ip, removed_paths):
    """Clean up backup files for paths that were removed from protection"""
    srv_idx_dir = os.path.join(INDEX, ip)
    srv_storage_dir = os.path.join(STORAGE, ip)
    
    for path in removed_paths:
        # Calculate index filename
        index_filename = f"{hashlib.md5(path.encode()).hexdigest()}.json"
        index_file = os.path.join(srv_idx_dir, index_filename)
        
        if os.path.exists(index_file):
            # Load index to find all backup files
            with open(index_file, 'r') as f:
                history = json.load(f)
            
            # Delete all physical backup files
            for version in history:
                storage_file = version.get('storage_file')
                if storage_file and os.path.exists(storage_file):
                    os.remove(storage_file)
                    logger.info(f"Removed backup file: {storage_file}")
            
            # Remove index file
            os.remove(index_file)
            logger.info(f"Removed index file: {index_file}")


@app.route('/api/explore')
@login_required
def explore():
    ip = request.args.get('ip')
    path = request.args.get('path', '/')
    inv = get_inventory()
    srv = inv.get(ip)
    
    if not srv:
        return jsonify({"error": "Server not found"}), 404
    
    try:
        # Escape path for shell
        escaped_path = path.replace("'", "'\\''")
        raw = run_ssh(srv, f"sudo ls -1Ap '{escaped_path}' 2>/dev/null")
        lines = raw.strip().splitlines()
        
        folders = []
        files = []
        
        for line in lines:
            if not line or line in ['.', '..']:
                continue
            
            name = line.rstrip('/')
            is_dir = line.endswith('/')
            
            # Properly join paths
            if path.endswith('/'):
                full_path = path + name
            else:
                full_path = path + '/' + name
            
            item = {'name': name, 'path': full_path, 'is_dir': is_dir}
            
            if is_dir:
                folders.append(item)
            else:
                files.append(item)
        
        # Sort alphabetically
        return jsonify(sorted(folders, key=lambda x: x['name'].lower()) + 
                      sorted(files, key=lambda x: x['name'].lower()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _is_text_file(file_type_output):
    """Check if file appears to be text based on file(1) output. Avoids false positives from mime-encoding."""
    lower = file_type_output.lower()
    text_indicators = ('text', 'ascii', 'utf-8', 'json', 'xml', 'empty', 'script')
    return any(ind in lower for ind in text_indicators)


@app.route('/api/preview')
@login_required
def preview():
    ip = request.args.get('ip')
    path = request.args.get('path')
    inv = get_inventory()
    srv = inv.get(ip)
    
    if not srv:
        return jsonify({"content": "Server not found"}), 404
    
    try:
        escaped_path = path.replace("'", "'\\''")
        
        # 1. Check file size - max 1MB (same as backup limit)
        size_result = run_ssh(srv, f"sudo stat -c '%s' '{escaped_path}' 2>/dev/null || echo '0'")
        try:
            size = int(size_result.strip())
        except ValueError:
            size = 0
        if size > MAX_FILE_SIZE_BYTES:
            return jsonify({
                "content": f"Preview not available\n\nFile exceeds 1MB size limit ({size / 1024 / 1024:.2f} MB).\nPreview is only available for files up to 1MB."
            })
        
        # 2. Check if text - use file -Lb (description) instead of mime-encoding to reduce false binary positives
        file_type_result = run_ssh(srv, f"sudo file -Lb '{escaped_path}' 2>/dev/null")
        file_type = file_type_result.strip()
        
        if not _is_text_file(file_type):
            return jsonify({
                "content": f"Preview not available\n\nThis file appears to be binary.\nFile type: {file_type}\n\nPreview is only available for text files."
            })
        
        # 3. Show content (first 500 lines)
        content = run_ssh(srv, f"sudo head -n 500 '{escaped_path}' 2>/dev/null")
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"content": f"Error reading file: {str(e)}"})

@app.route('/api/file-size')
@login_required
def file_size():
    """Get file size in bytes"""
    ip = request.args.get('ip')
    path = request.args.get('path')
    inv = get_inventory()
    srv = inv.get(ip)
    
    if not srv:
        return jsonify({"error": "Server not found"}), 404
    
    try:
        escaped_path = path.replace("'", "'\\''")
        result = run_ssh(srv, f"sudo stat -c '%s' '{escaped_path}' 2>/dev/null || echo '0'")
        size = int(result.strip())
        return jsonify({"size": size})
    except:
        return jsonify({"size": 0})

@app.route('/api/history')
@login_required
def history():
    ip = request.args.get('ip')
    path = request.args.get('path')
    
    srv_idx = os.path.join(INDEX, ip)
    index_file = os.path.join(srv_idx, f"{hashlib.md5(path.encode()).hexdigest()}.json")
    
    if os.path.exists(index_file):
        with open(index_file, 'r') as f:
            history = json.load(f)
            return jsonify(sorted(history, key=lambda x: x['date'], reverse=True))
    
    return jsonify([])

@app.route('/api/backup/content')
@login_required
def backup_content():
    """Get content of a specific backup version"""
    ip = request.args.get('ip')
    path = request.args.get('path')
    date = request.args.get('date')
    
    if not all([ip, path, date]):
        return jsonify({"error": "IP, path, and date required"}), 400
    
    # Find the backup in index
    srv_idx = os.path.join(INDEX, ip)
    index_file = os.path.join(srv_idx, f"{hashlib.md5(path.encode()).hexdigest()}.json")
    
    if not os.path.exists(index_file):
        return jsonify({"error": "Backup index not found"}), 404
    
    with open(index_file, 'r') as f:
        history = json.load(f)
        backup = next((v for v in history if v['date'] == date), None)
        
        if not backup:
            return jsonify({"error": "Backup version not found"}), 404
        
        storage_file = backup.get('storage_file')
        if not storage_file or not os.path.exists(storage_file):
            return jsonify({"error": "Backup file not found on disk"}), 404
    
    # Check if file is empty
    if os.path.getsize(storage_file) == 0:
        return jsonify({"error": "Backup file is empty (0 bytes)"}), 500
    
    try:
        # Decompress and read first 500 lines
        result = subprocess.check_output(f"zcat {storage_file} | head -n 500", shell=True, stderr=subprocess.PIPE)
        content = result.decode('utf-8', errors='ignore')
        return jsonify({"content": content})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Decompression failed: {e.stderr.decode('utf-8', errors='ignore')}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error reading backup: {str(e)}"}), 500

@app.route('/api/backup/delete', methods=['DELETE'])
@login_required
def delete_backup():
    """Delete a specific backup version"""
    data = request.json
    ip = data.get('ip')
    path = data.get('path')
    date = data.get('date')
    
    if not all([ip, path, date]):
        return jsonify({"status": "error", "message": "Missing parameters"}), 400
    
    # Load index
    srv_idx = os.path.join(INDEX, ip)
    index_file = os.path.join(srv_idx, f"{hashlib.md5(path.encode()).hexdigest()}.json")
    
    if not os.path.exists(index_file):
        return jsonify({"status": "error", "message": "No backup history found"}), 404
    
    with open(index_file, 'r') as f:
        history = json.load(f)
    
    # Find and remove the version
    backup_to_delete = None
    updated_history = []
    for v in history:
        if v['date'] == date:
            backup_to_delete = v
        else:
            updated_history.append(v)
    
    if not backup_to_delete:
        return jsonify({"status": "error", "message": "Version not found"}), 404
    
    # Delete physical file
    storage_file = backup_to_delete.get('storage_file')
    if storage_file and os.path.exists(storage_file):
        try:
            os.remove(storage_file)
            logger.info(f"Deleted backup file: {storage_file}")
        except Exception as e:
            logger.error(f"ERROR: Failed to delete backup file {storage_file}: {str(e)}")
    
    # Save updated history or delete index if empty
    if len(updated_history) == 0:
        os.remove(index_file)
    else:
        with open(index_file, 'w') as f:
            json.dump(updated_history, f, indent=4)
    
    logger.info(f"User {session.get('username')} deleted backup version: {path} from {date}")
    return jsonify({"status": "success", "message": "Backup version deleted"})

@app.route('/api/restore', methods=['POST'])
@login_required
def restore():
    data = request.json
    inv = get_inventory()
    srv = inv.get(data['ip'])
    
    if not srv:
        return jsonify({"status": "error", "message": "Server not found"}), 404
    
    remote_path = data['path']
    metadata = data.get('metadata', {})
    storage_file = metadata.get('storage_file')
    
    if not storage_file or not os.path.exists(storage_file):
        return jsonify({"status": "error", "message": "Backup file not found"}), 404
    
    # Restore with .restore suffix
    remote_dest = remote_path + ".restore"
    escaped_dest = remote_dest.replace("'", "'\\''")
    escaped_orig = remote_path.replace("'", "'\\''")
    
    # Check if SSH key exists
    ssh_key_option = ""
    if os.path.exists(SSH_KEY_FILE):
        ssh_key_option = f"-i {SSH_KEY_FILE}"
    
    # Transfer file - use sudo tee so non-root users (e.g. ansible) can write to /etc etc.
    cmd = f"zcat {storage_file} | ssh -q {ssh_key_option} -p {str(srv.get('port', 22))} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR {srv['user']}@{srv['ip']} 'sudo tee {escaped_dest} > /dev/null'"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            err = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Restore transfer failed: {err}")
            return jsonify({"status": "error", "message": f"Restore failed: {err.strip() or 'Permission denied or transfer error'}"}), 500
        
        # Apply permissions (sudo required - file may be owned by root)
        if metadata.get('permissions'):
            perm_cmd = f"sudo chmod {metadata['permissions']} '{escaped_dest}'"
            run_ssh(srv, perm_cmd)
        
        # Apply owner:group
        if metadata.get('owner') and metadata.get('group'):
            chown_cmd = f"chown {metadata['owner']}:{metadata['group']} '{escaped_dest}'"
            run_ssh(srv, f"sudo {chown_cmd}")
        
        # Apply SELinux context
        if metadata.get('selinux_context'):
            # Copy context from original file
            selinux_cmd = f"chcon --reference='{escaped_orig}' '{escaped_dest}' 2>/dev/null || restorecon -v '{escaped_dest}'"
            run_ssh(srv, f"sudo {selinux_cmd}")
        
        logger.info(f"User {session.get('username')} restored file: {remote_path} to {remote_dest}")
        return jsonify({"status": "success", "message": f"Restored to {remote_dest}"})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Restore failed"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/sync', methods=['POST'])
@login_required
def sync():
    """Manual sync trigger"""
    try:
        sync_logger.info(f"SYNC STARTED via manual click by user {session.get('username')}")
        results = sync_all_servers()
        return jsonify({"status": "success", "results": results})
    except Exception as e:
        sync_logger.error(f"ERROR: Manual sync failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        data = request.json
        save_settings(data)
        logger.info(f"User {session.get('username')} updated settings")
        return jsonify({"status": "success"})
    
    return jsonify(get_settings())

@app.route('/api/ssh-key', methods=['GET', 'POST', 'DELETE'])
@login_required
def ssh_key():
    """Manage SSH private key"""
    if request.method == 'POST':
        key_content = request.json.get('key')
        
        if not key_content:
            return jsonify({"status": "error", "message": "No key provided"}), 400
        
        # Clean and validate key
        key_content = key_content.strip()
        
        # Validate key format (basic check)
        if not key_content.startswith('-----BEGIN') or 'PRIVATE KEY' not in key_content:
            return jsonify({"status": "error", "message": "Invalid private key format"}), 400
        
        # Ensure key ends with newline
        if not key_content.endswith('\n'):
            key_content += '\n'
        
        # Save key with proper permissions
        try:
            with open(SSH_KEY_FILE, 'w') as f:
                f.write(key_content)
            os.chmod(SSH_KEY_FILE, 0o600)  # Read/write for owner only
            logger.info(f"User {session.get('username')} uploaded SSH private key")
            return jsonify({"status": "success", "message": "SSH key saved successfully"})
        except Exception as e:
            logger.error(f"ERROR: Failed to save SSH key: {str(e)}")
            return jsonify({"status": "error", "message": "Failed to save key"}), 500
    
    elif request.method == 'DELETE':
        if os.path.exists(SSH_KEY_FILE):
            os.remove(SSH_KEY_FILE)
            logger.info(f"User {session.get('username')} deleted SSH private key")
            return jsonify({"status": "success", "message": "SSH key deleted"})
        return jsonify({"status": "error", "message": "No key found"}), 404
    
    else:  # GET
        has_key = os.path.exists(SSH_KEY_FILE)
        return jsonify({"has_key": has_key})

@app.route('/api/test-connection', methods=['POST'])
@login_required
def test_connection():
    """Test SSH connection and sudo (for non-root users)"""
    data = request.json
    srv = {
        'ip': data.get('ip'),
        'port': data.get('port', '22'),
        'user': data.get('user', 'root')
    }
    
    try:
        result = run_ssh(srv, 'echo "Connection OK"')
        if 'Connection OK' not in result:
            return jsonify({"status": "error", "message": "Unexpected response"}), 500
        
        # For non-root users, validate passwordless sudo (required for backup/restore)
        if srv.get('user', 'root') != 'root':
            try:
                run_ssh(srv, 'sudo -n true 2>/dev/null')
            except Exception as e:
                err = str(e).lower()
                return jsonify({
                    "status": "error",
                    "message": "SSH OK, but sudo validation failed. Non-root user needs NOPASSWD sudo for: tee, chmod, chown, chcon, cat, stat, md5sum, file, head, ls. Example sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/tee, /usr/bin/chmod, /usr/bin/chown, /bin/cat, /usr/bin/stat, /usr/bin/md5sum, /usr/bin/file, /usr/bin/head, /bin/ls, /usr/bin/chcon, /usr/sbin/restorecon"
                }), 500
        
        msg = "Connection and sudo OK" if srv.get('user', 'root') != 'root' else "Connection successful"
        return jsonify({"status": "success", "message": msg})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
