from flask import Flask, render_template, request, jsonify, session, send_from_directory
from flask_cors import CORS
import hashlib
import requests
import os
import json
import time
import re
import base64
import sqlite3
from datetime import datetime, timedelta
from threading import Thread
import logging
from werkzeug.utils import secure_filename
import tempfile
import shutil
import uuid

# Try importing optional dependencies
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available. File type detection will be basic.")

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False
    print("Warning: GitPython not available. GitHub scanning will be limited.")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['BOT_DATA_FOLDER'] = '/tmp/bot_data'

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['BOT_DATA_FOLDER'], exist_ok=True)

CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
VT_API_KEY = os.environ.get('VT_API_KEY', '2c275dc00ce1271ad55f7cffb63fb88ec15640f37ec619554d56b8318f4a64d8')
OWNER_NAME = 'Adixtpy'
BOT_NAME = 'Aditya'

# Database setup (using file-based SQLite in /tmp for Vercel)
def init_db():
    db_path = '/tmp/bot_database.db'
    conn = sqlite3.connect(db_path, check_same_thread=False)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id TEXT PRIMARY KEY,
                  username TEXT,
                  first_seen TIMESTAMP,
                  last_seen TIMESTAMP,
                  scan_count INTEGER DEFAULT 0)''')
    
    # Scan history table
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (scan_id TEXT PRIMARY KEY,
                  user_id TEXT,
                  scan_type TEXT,
                  target TEXT,
                  risk_score INTEGER,
                  risk_level TEXT,
                  threats_found INTEGER,
                  timestamp TIMESTAMP,
                  result_data TEXT)''')
    
    # Bot conversations table
    c.execute('''CREATE TABLE IF NOT EXISTS bot_conversations
                 (conv_id TEXT PRIMARY KEY,
                  user_id TEXT,
                  message TEXT,
                  response TEXT,
                  timestamp TIMESTAMP)''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Simplified threat patterns
THREAT_PATTERNS = {
    'malware': [
        (r'eval\s*\(\s*base64_decode', 'CRITICAL', 'Encoded malware payload'),
        (r'system\s*\(\s*\$_', 'CRITICAL', 'Remote command execution'),
        (r'file_put_contents\s*\(\s*.*?\s*,\s*.*?\$_', 'HIGH', 'Remote file write'),
    ],
    'backdoors': [
        (r'base64_decode\(\s*[\'"][A-Za-z0-9+/=]{100,}', 'CRITICAL', 'Base64 encoded backdoor'),
        (r'gzinflate\(\s*base64_decode', 'CRITICAL', 'Compressed backdoor'),
    ],
    'credentials': [
        (r'password\s*=\s*[\'"][^\'"]{8,}', 'MEDIUM', 'Hardcoded password'),
        (r'api[_-]?key\s*=\s*[\'"][A-Za-z0-9]{16,}', 'HIGH', 'Hardcoded API key'),
        (r'ssh-rsa\s+[A-Za-z0-9+/]{100,}', 'HIGH', 'Embedded SSH key'),
    ],
    'network': [
        (r'curl_exec\s*\(.*?\$_', 'HIGH', 'CURL with user input'),
        (r'fsockopen\s*\(\s*[\'"]\d+\.\d+\.\d+\.\d+', 'MEDIUM', 'Hardcoded IP connection'),
    ]
}

# Bot responses
BOT_RESPONSES = {
    'greeting': [
        f"Hello! I'm {BOT_NAME}, your security assistant. How can I help you today?",
        f"Hi there! Ready to scan some files or check URLs?",
    ],
    'file_scan': [
        "Upload any file and I'll scan it for malware and threats!",
        "Our file scanner checks for viruses, backdoors, and suspicious code.",
    ],
    'url_scan': [
        "Enter a URL and I'll check if it's safe to visit.",
        "URL scanning includes malware detection and phishing checks.",
    ],
    'github_scan': [
        "Paste a GitHub repository URL and I'll analyze the code for security issues.",
        "Repository scanning finds hardcoded secrets and vulnerabilities.",
    ],
    'help': [
        "I can help with:\n• File scanning\n• URL safety checks\n• GitHub repo analysis\n• Threat explanations",
        "Just ask me about files, URLs, or GitHub repositories!",
    ],
    'default': [
        f"I'm {BOT_NAME}. Try asking about file scanning, URL checking, or GitHub analysis.",
        "Not sure? Ask me about files, URLs, or GitHub repositories!",
    ]
}

# Simple Bot Class
class SimpleBot:
    def process_message(self, message):
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['hi', 'hello', 'hey']):
            return self.get_response('greeting')
        elif any(word in message_lower for word in ['file', 'document', 'upload']):
            return self.get_response('file_scan')
        elif any(word in message_lower for word in ['url', 'link', 'website']):
            return self.get_response('url_scan')
        elif any(word in message_lower for word in ['github', 'git', 'repo']):
            return self.get_response('github_scan')
        elif any(word in message_lower for word in ['help', 'what', 'how']):
            return self.get_response('help')
        else:
            return self.get_response('default')
    
    def get_response(self, key):
        responses = BOT_RESPONSES.get(key, BOT_RESPONSES['default'])
        return responses[hash(datetime.now().isoformat()) % len(responses)]

# Simple Scanner Class
class SimpleScanner:
    def scan_file(self, file_path, filename):
        results = {
            'threats': [],
            'risk_score': 0,
            'file_info': {
                'name': filename,
                'size': os.path.getsize(file_path)
            },
            'hashes': self.calculate_hashes(file_path)
        }
        
        # Get file type
        if MAGIC_AVAILABLE:
            try:
                mime = magic.from_file(file_path, mime=True)
                results['file_info']['mime_type'] = mime
            except:
                results['file_info']['mime_type'] = 'unknown'
        else:
            # Basic file type detection
            ext = os.path.splitext(filename)[1].lower()
            results['file_info']['mime_type'] = f'application/{ext[1:] if ext else "octet-stream"}'
        
        # Scan text files
        if self.is_text_file(filename):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    threats = self.scan_content(content, filename)
                    results['threats'].extend(threats)
            except:
                pass
        
        # Calculate risk score
        results['risk_score'] = len(results['threats']) * 15
        if results['risk_score'] > 100:
            results['risk_score'] = 100
            
        # Determine risk level
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        return results
    
    def calculate_hashes(self, file_path):
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except:
            pass
        return hashes
    
    def is_text_file(self, filename):
        text_extensions = ['.txt', '.py', '.js', '.html', '.css', '.json', '.xml', '.yml', '.md', '.php', '.asp', '.java', '.cpp', '.h', '.c', '.sh', '.bat', '.ps1']
        ext = os.path.splitext(filename)[1].lower()
        return ext in text_extensions
    
    def scan_content(self, content, filename):
        threats = []
        for category, patterns in THREAT_PATTERNS.items():
            for pattern, severity, description in patterns:
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        threats.append({
                            'category': category,
                            'severity': severity,
                            'description': description,
                            'match': match.group()[:100],
                            'line': self.get_line_number(content, match.start()),
                            'file': filename
                        })
                except:
                    continue
        return threats
    
    def get_line_number(self, content, position):
        return content.count('\n', 0, position) + 1
    
    def get_risk_level(self, score):
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        elif score >= 10:
            return 'LOW'
        else:
            return 'CLEAN'

# Initialize scanner and bot
scanner = SimpleScanner()
bot = SimpleBot()

# Routes
@app.route('/')
def index():
    return render_template('index.html', owner=OWNER_NAME, bot_name=BOT_NAME)

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Secure filename and save temporarily
    filename = secure_filename(file.filename)
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{uuid.uuid4().hex}_{filename}")
    file.save(temp_path)
    
    try:
        # Scan file
        results = scanner.scan_file(temp_path, filename)
        
        # Save to history
        save_scan_history(
            user_id=request.remote_addr,
            scan_type='file',
            target=filename,
            risk_score=results['risk_score'],
            risk_level=results['risk_level'],
            threats_found=len(results['threats']),
            result_data=json.dumps(results)
        )
        
        return jsonify(results)
    
    finally:
        # Clean up temp file
        try:
            os.remove(temp_path)
        except:
            pass

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Validate and normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    results = {
        'url': url,
        'threats': [],
        'risk_score': 0,
        'domain_info': {}
    }
    
    try:
        # Fetch URL content
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Scan content
        content = response.text
        threats = scanner.scan_content(content, url)
        results['threats'] = threats
        
        # Get domain info
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        results['domain_info'] = {
            'domain': parsed.netloc,
            'scheme': parsed.scheme,
            'status_code': response.status_code,
            'content_type': response.headers.get('Content-Type', ''),
            'content_length': len(content)
        }
        
        # Calculate risk score
        results['risk_score'] = len(threats) * 15
        if results['risk_score'] > 100:
            results['risk_score'] = 100
            
        results['risk_level'] = scanner.get_risk_level(results['risk_score'])
        
        # Save to history
        save_scan_history(
            user_id=request.remote_addr,
            scan_type='url',
            target=url,
            risk_score=results['risk_score'],
            risk_level=results['risk_level'],
            threats_found=len(threats),
            result_data=json.dumps(results)
        )
        
    except requests.exceptions.RequestException as e:
        results['error'] = str(e)
        results['risk_level'] = 'ERROR'
        results['risk_score'] = 0
    
    return jsonify(results)

@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    data = request.json
    repo_url = data.get('url', '')
    
    if not repo_url or 'github.com' not in repo_url:
        return jsonify({'error': 'Invalid GitHub URL'}), 400
    
    results = {
        'repo_url': repo_url,
        'repo_name': repo_url.split('/')[-1].replace('.git', ''),
        'threats': [],
        'risk_score': 0,
        'files_scanned': 0
    }
    
    try:
        # Use GitHub API instead of cloning
        api_url = repo_url.replace('github.com', 'api.github.com/repos')
        if api_url.endswith('.git'):
            api_url = api_url[:-4]
        
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            repo_data = response.json()
            results['description'] = repo_data.get('description')
            results['stars'] = repo_data.get('stargazers_count', 0)
            results['forks'] = repo_data.get('forks_count', 0)
            
            # Get repo contents (limited to root directory)
            contents_url = f"{api_url}/contents"
            contents_response = requests.get(contents_url, timeout=10)
            
            if contents_response.status_code == 200:
                contents = contents_response.json()
                results['files_scanned'] = len(contents)
                
                # Scan README if exists
                for item in contents:
                    if item['name'].lower() == 'readme.md':
                        readme_response = requests.get(item['download_url'], timeout=10)
                        if readme_response.status_code == 200:
                            threats = scanner.scan_content(readme_response.text, 'README.md')
                            results['threats'].extend(threats)
        
        # Calculate risk score
        results['risk_score'] = len(results['threats']) * 15
        if results['risk_score'] > 100:
            results['risk_score'] = 100
            
        results['risk_level'] = scanner.get_risk_level(results['risk_score'])
        
        # Save to history
        save_scan_history(
            user_id=request.remote_addr,
            scan_type='github',
            target=repo_url,
            risk_score=results['risk_score'],
            risk_level=results['risk_level'],
            threats_found=len(results['threats']),
            result_data=json.dumps(results)
        )
        
    except Exception as e:
        results['error'] = str(e)
        results['risk_level'] = 'ERROR'
    
    return jsonify(results)

@app.route('/api/bot/message', methods=['POST'])
def bot_message():
    data = request.json
    user_message = data.get('message', '')
    
    # Get bot response
    response = bot.process_message(user_message)
    
    return jsonify({
        'response': response,
        'bot_name': BOT_NAME,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    limit = int(request.args.get('limit', 10))
    db_path = '/tmp/bot_database.db'
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''SELECT scan_id, scan_type, target, risk_score, risk_level, threats_found, timestamp 
                     FROM scan_history ORDER BY timestamp DESC LIMIT ?''', (limit,))
        rows = c.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'id': row[0],
                'type': row[1],
                'target': row[2][:50] + '...' if len(row[2]) > 50 else row[2],
                'risk_score': row[3],
                'risk_level': row[4],
                'threats_found': row[5],
                'timestamp': row[6]
            })
        
        return jsonify(history)
    except:
        return jsonify([])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    db_path = '/tmp/bot_database.db'
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Total scans
        c.execute('SELECT COUNT(*) FROM scan_history')
        total_scans = c.fetchone()[0] or 0
        
        # Threats found
        c.execute('SELECT SUM(threats_found) FROM scan_history')
        threats_found = c.fetchone()[0] or 0
        
        # Clean files
        c.execute('SELECT COUNT(*) FROM scan_history WHERE threats_found = 0')
        clean_files = c.fetchone()[0] or 0
        
        # Average risk score
        c.execute('SELECT AVG(risk_score) FROM scan_history')
        avg_risk = c.fetchone()[0] or 0
        
        conn.close()
        
        return jsonify({
            'total_scans': total_scans,
            'threats_found': threats_found,
            'clean_files': clean_files,
            'avg_risk_score': round(avg_risk, 2)
        })
    except:
        return jsonify({
            'total_scans': 0,
            'threats_found': 0,
            'clean_files': 0,
            'avg_risk_score': 0
        })

def save_scan_history(user_id, scan_type, target, risk_score, risk_level, threats_found, result_data):
    """Save scan to database"""
    try:
        db_path = '/tmp/bot_database.db'
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        scan_id = hashlib.md5(f"{user_id}{target}{time.time()}".encode()).hexdigest()[:16]
        c.execute('''INSERT INTO scan_history 
                    (scan_id, user_id, scan_type, target, risk_score, risk_level, threats_found, timestamp, result_data) 
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                 (scan_id, user_id, scan_type, target, risk_score, risk_level, threats_found, datetime.now().isoformat(), result_data))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error saving scan history: {e}")

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# For local development
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
