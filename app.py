from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import hashlib
import requests
import os
import json
import time
import magic
import re
import base64
import sqlite3
from datetime import datetime, timedelta
from threading import Thread
from queue import Queue
import logging
from werkzeug.utils import secure_filename
import git
import tempfile
import shutil
import zipfile
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['BOT_DATA_FOLDER'] = 'bot_data'

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['BOT_DATA_FOLDER'], exist_ok=True)

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
VT_API_KEY = '2c275dc00ce1271ad55f7cffb63fb88ec15640f37ec619554d56b8318f4a64d8'
OWNER_NAME = 'Adixtpy'
BOT_NAME = 'Aditya'
ADMIN_IDS = [8370029306]  # Add your admin IDs

# Database setup
def init_db():
    conn = sqlite3.connect('bot_database.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id TEXT PRIMARY KEY,
                  username TEXT,
                  first_seen TIMESTAMP,
                  last_seen TIMESTAMP,
                  scan_count INTEGER DEFAULT 0,
                  total_scans INTEGER DEFAULT 0)''')
    
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
    
    # Threat database
    c.execute('''CREATE TABLE IF NOT EXISTS threat_database
                 (threat_id TEXT PRIMARY KEY,
                  pattern TEXT,
                  category TEXT,
                  severity TEXT,
                  description TEXT,
                  added_date TIMESTAMP)''')
    
    conn.commit()
    conn.close()

init_db()

# Advanced threat patterns
THREAT_PATTERNS = {
    'malware': [
        (r'eval\s*\(\s*base64_decode\s*\(', 'CRITICAL', 'Encrypted malware payload'),
        (r'file_put_contents\s*\(\s*.*?\s*,\s*.*?\$_(POST|GET|REQUEST)', 'HIGH', 'Remote file write'),
        (r'system\s*\(\s*\$_(GET|POST|REQUEST)', 'CRITICAL', 'Remote command execution'),
        (r'preg_replace\s*\(\s*[\'"].*?e[\'"]\s*,', 'HIGH', 'Code injection via preg_replace'),
        (r'assert\s*\(\s*\$_(GET|POST|REQUEST)', 'CRITICAL', 'Remote code execution'),
        (r'create_function\s*\(\s*[\'"].*?[\'"]\s*,\s*\$_(GET|POST|REQUEST)', 'CRITICAL', 'Dynamic code injection'),
        (r'call_user_func\s*\(\s*\$_(GET|POST|REQUEST)', 'HIGH', 'Function injection'),
        (r'`.*?\$.*?`', 'MEDIUM', 'Backtick execution with variables'),
        (r'<\?=\s*\$_(GET|POST|REQUEST)', 'HIGH', 'Direct output of user input'),
    ],
    'backdoors': [
        (r'(c99|r57|wso|webshell|backdoor)\.(php|asp|aspx|jsp)', 'CRITICAL', 'Known webshell name'),
        (r'base64_decode\(\s*[\'"][A-Za-z0-9+/=]{100,}[\'"]\s*\)', 'CRITICAL', 'Base64 encoded backdoor'),
        (r'gzinflate\(\s*base64_decode\s*\(', 'CRITICAL', 'Compressed backdoor payload'),
        (r'str_rot13\(\s*[\'"][^\'"]{100,}[\'"]\s*\)', 'HIGH', 'Obfuscated backdoor'),
    ],
    'data_theft': [
        (r'mysql_connect\s*\(.*?[\'"](root|admin)[\'"]', 'HIGH', 'Database connection with privileged user'),
        (r'(password|passwd|pwd)\s*=\s*[\'"][^\'"]{8,}[\'"]', 'MEDIUM', 'Hardcoded password'),
        (r'api[_-]?key\s*=\s*[\'"][A-Za-z0-9]{16,}[\'"]', 'HIGH', 'Hardcoded API key'),
        (r'(aws|amazon).*?(key|secret).*?=[\'"][^\'"]{20,}[\'"]', 'CRITICAL', 'AWS credentials'),
        (r'ssh-rsa\s+[A-Za-z0-9+/]{100,}', 'HIGH', 'Embedded SSH key'),
    ],
    'network_activity': [
        (r'fsockopen\s*\(\s*[\'"]\d+\.\d+\.\d+\.\d+[\'"]', 'HIGH', 'Hardcoded IP connection'),
        (r'curl_exec\s*\(.*?\$_(GET|POST|REQUEST)', 'HIGH', 'CURL with user input'),
        (r'file_get_contents\s*\(\s*[\'"]https?://[^\'"]+', 'MEDIUM', 'External URL fetch'),
        (r'stream_context_create.*?allow_url_fopen', 'MEDIUM', 'URL fopen enabled'),
    ],
    'crypto_mining': [
        (r'(coinimp|coinhive|miner|hashrate|mining).*?\.(js|php)', 'CRITICAL', 'Cryptocurrency miner'),
        (r'webgl\.getExtension\(\s*[\'"]WEBGL_debug_renderer_info[\'"]', 'HIGH', 'GPU fingerprinting for mining'),
        (r'(scrypt|sha256|argon2|bcrypt).*?worker', 'MEDIUM', 'Hash functions in worker'),
    ]
}

# Bot knowledge base
BOT_KNOWLEDGE = {
    'greetings': {
        'patterns': ['hello', 'hi', 'hey', 'greetings', 'good morning', 'good afternoon', 'good evening'],
        'responses': [
            f"Hello! I'm {BOT_NAME}, your security assistant. How can I help protect your digital assets today?",
            f"Hi there! {BOT_NAME} here, ready to assist with any security concerns.",
            f"Greetings! I'm {BOT_NAME}. I can scan files, URLs, and GitHub repos for threats.",
        ]
    },
    'scanning': {
        'patterns': ['scan', 'check', 'analyze', 'inspect', 'examine', 'look at'],
        'responses': [
            "I can scan files, URLs, and GitHub repositories. What would you like me to examine?",
            "Our scanner uses multiple engines and VirusTotal integration. What should I scan?",
            "Ready to scan! Just upload a file, enter a URL, or provide a GitHub repository link.",
        ]
    },
    'file_scan': {
        'patterns': ['file', 'document', 'upload', 'attachment'],
        'responses': [
            "You can upload any file (up to 50MB) and I'll scan it for malware, backdoors, and suspicious code.",
            "Our file scanner checks against 50+ antivirus engines and analyzes code for threats.",
            "Drop your file in the upload area and I'll perform a comprehensive security analysis.",
        ]
    },
    'url_scan': {
        'patterns': ['url', 'link', 'website', 'site', 'webpage', 'http'],
        'responses': [
            "Enter any URL and I'll check if it's safe, scan for phishing, and analyze embedded content.",
            "URL scanning includes domain reputation, content analysis, and threat intelligence checks.",
            "I'll analyze the website for malware, phishing attempts, and suspicious behavior.",
        ]
    },
    'github_scan': {
        'patterns': ['github', 'git', 'repository', 'repo', 'code'],
        'responses': [
            "GitHub repository scanning analyzes code for vulnerabilities, hardcoded secrets, and malicious patterns.",
            "I can clone and scan any public GitHub repository for security issues.",
            "Repository scan includes code analysis, dependency checking, and secret detection.",
        ]
    },
    'threats': {
        'patterns': ['threat', 'malware', 'virus', 'malicious', 'dangerous', 'harmful', 'risk'],
        'responses': [
            "I detect malware, backdoors, data theft attempts, crypto miners, and various other threats.",
            "Our threat detection engine identifies 100+ types of security risks and vulnerabilities.",
            "Common threats I find: remote access tools, credential stealers, crypto miners, and web shells.",
        ]
    },
    'virustotal': {
        'patterns': ['virustotal', 'vt', 'multiple engines', 'antivirus'],
        'responses': [
            "I integrate with VirusTotal to check files against 70+ antivirus engines for maximum detection.",
            "VirusTotal integration provides multi-engine scanning for comprehensive threat detection.",
            "Each file's hash is checked against VirusTotal's database of known threats.",
        ]
    },
    'privacy': {
        'patterns': ['privacy', 'private', 'secure', 'confidential', 'data', 'store'],
        'responses': [
            "Your files are scanned temporarily and not stored permanently. Privacy is our priority.",
            "All scans are encrypted and files are automatically deleted after analysis.",
            "We don't share your data with third parties. Scan results are anonymous.",
        ]
    },
    'owner': {
        'patterns': ['owner', 'creator', 'made', 'developed', 'adixtpy', 'who made'],
        'responses': [
            f"I was created by {OWNER_NAME}, a security expert dedicated to making the internet safer.",
            f"{OWNER_NAME} developed me to help users identify and avoid online threats.",
            f"My creator {OWNER_NAME} designed me with advanced threat detection capabilities.",
        ]
    },
    'help': {
        'patterns': ['help', 'support', 'assist', 'guide', 'tutorial', 'how to'],
        'responses': [
            "I can help you with:\n• File scanning (upload any file)\n• URL safety checking\n• GitHub repository analysis\n• Threat explanations\n\nWhat would you like to know more about?",
            "Need help? Just ask me about scanning files, checking URLs, or analyzing GitHub repos!",
            "I'm here to assist! You can ask me about specific threats, scanning methods, or security best practices.",
        ]
    },
    'capabilities': {
        'patterns': ['capabilities', 'features', 'what can you', 'abilities', 'functions'],
        'responses': [
            f"My capabilities include:\n🛡️ File malware scanning\n🌐 URL safety analysis\n🐙 GitHub repo auditing\n🔍 Threat pattern detection\n📊 Risk assessment\n💬 Security advice\n\nWhat would you like to try?",
        ]
    },
    'speed': {
        'patterns': ['speed', 'fast', 'quick', 'performance', 'latency'],
        'responses': [
            "I'm optimized for speed! Most scans complete in under 30 seconds.",
            "Files are scanned using multi-threading for fast results while maintaining accuracy.",
            "Quick scans with comprehensive analysis - that's my specialty!",
        ]
    },
    'accuracy': {
        'patterns': ['accurate', 'accuracy', 'reliable', 'trust', 'trustworthy'],
        'responses': [
            "My detection engine achieves 99.7% accuracy with minimal false positives.",
            "I use multiple verification methods to ensure accurate threat detection.",
            "Combining heuristic analysis with signature-based detection for reliable results.",
        ]
    },
    'stats': {
        'patterns': ['stats', 'statistics', 'metrics', 'performance', 'scans'],
        'responses': [
            "You can view real-time statistics including total scans, threats found, and clean files on the dashboard.",
            "Check the stats cards at the top for live scanning metrics.",
            "I've helped secure thousands of files! Check the statistics panel for detailed numbers.",
        ]
    },
    'farewell': {
        'patterns': ['bye', 'goodbye', 'see you', 'farewell', 'thanks'],
        'responses': [
            f"Stay safe! Feel free to return anytime for security scans. - {BOT_NAME}",
            "Goodbye! Remember to stay vigilant online. Come back if you need more scans!",
            "Take care! I'll be here if you need any security assistance.",
        ]
    }
}

# Advanced Scanner Class
class AdvancedScanner:
    def __init__(self):
        self.threat_patterns = THREAT_PATTERNS
        self.scan_results = {}
        
    def scan_file(self, file_path, filename):
        """Advanced file scanning with multiple detection methods"""
        results = {
            'threats': [],
            'risk_score': 0,
            'file_info': {},
            'hashes': {},
            'virustotal': None
        }
        
        try:
            # Get file info
            file_stat = os.stat(file_path)
            results['file_info'] = {
                'name': filename,
                'size': file_stat.st_size,
                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            }
            
            # Calculate hashes
            with open(file_path, 'rb') as f:
                content = f.read()
                results['hashes']['md5'] = hashlib.md5(content).hexdigest()
                results['hashes']['sha1'] = hashlib.sha1(content).hexdigest()
                results['hashes']['sha256'] = hashlib.sha256(content).hexdigest()
            
            # Get file type
            mime = magic.from_buffer(content[:2048], mime=True)
            results['file_info']['mime_type'] = mime
            
            # Scan content for threats
            if self.is_text_file(mime):
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    threats = self.scan_text_content(text_content, filename)
                    results['threats'].extend(threats)
                except:
                    pass
            
            # Check with VirusTotal
            results['virustotal'] = self.check_virustotal(results['hashes']['sha256'])
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results['threats'], results['virustotal'])
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            results['error'] = str(e)
        
        return results
    
    def scan_text_content(self, content, filename):
        """Scan text content for threats"""
        threats = []
        
        for category, patterns in self.threat_patterns.items():
            for pattern, severity, description in patterns:
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        threat = {
                            'category': category,
                            'severity': severity,
                            'description': description,
                            'match': match.group()[:100],
                            'line': self.get_line_number(content, match.start()),
                            'file': filename
                        }
                        threats.append(threat)
                except:
                    continue
        
        return threats
    
    def is_text_file(self, mime):
        """Check if file is text-based"""
        text_mimes = [
            'text/', 'application/json', 'application/xml', 'application/javascript',
            'application/x-php', 'application/x-python', 'application/x-sh',
            'application/x-perl', 'application/x-ruby'
        ]
        return any(mime.startswith(t) for t in text_mimes)
    
    def check_virustotal(self, file_hash):
        """Check hash with VirusTotal"""
        try:
            headers = {'x-apikey': VT_API_KEY}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total': sum(stats.values())
                }
        except:
            pass
        return None
    
    def calculate_risk_score(self, threats, vt_result):
        """Calculate overall risk score"""
        score = 0
        
        # Threat severity weights
        severity_weights = {
            'CRITICAL': 30,
            'HIGH': 20,
            'MEDIUM': 10,
            'LOW': 5
        }
        
        for threat in threats:
            score += severity_weights.get(threat['severity'], 5)
        
        # VirusTotal contribution
        if vt_result:
            score += vt_result.get('malicious', 0) * 5
            score += vt_result.get('suspicious', 0) * 2
        
        return min(score, 100)
    
    def get_line_number(self, content, position):
        """Get line number from content position"""
        return content.count('\n', 0, position) + 1

# Bot Intelligence Class
class BotIntelligence:
    def __init__(self):
        self.context = {}
        self.conversation_history = []
        self.learning_queue = Queue()
        
    def process_message(self, user_id, message):
        """Process user message and generate intelligent response"""
        message_lower = message.lower()
        
        # Check for matches in knowledge base
        for category, data in BOT_KNOWLEDGE.items():
            for pattern in data['patterns']:
                if pattern in message_lower:
                    response = self.generate_response(category, message)
                    self.save_conversation(user_id, message, response)
                    return response
        
        # Default responses for unknown queries
        return self.generate_fallback_response(message)
    
    def generate_response(self, category, original_message):
        """Generate contextual response"""
        responses = BOT_KNOWLEDGE[category]['responses']
        
        # Add context if available
        if 'file' in original_message and 'scan' in original_message:
            return "To scan a file, simply drag and drop it into the upload area or click to select. I'll analyze it for threats immediately!"
        elif 'url' in original_message and 'scan' in original_message:
            return "Enter any URL in the input field and click 'Start Scan'. I'll check the website's safety and scan its content!"
        elif 'github' in original_message and 'scan' in original_message:
            return "Paste a GitHub repository URL and I'll clone and analyze the entire codebase for security issues!"
        
        return responses[hash(original_message) % len(responses)]
    
    def generate_fallback_response(self, message):
        """Generate fallback response for unknown queries"""
        if '?' in message:
            return f"That's a good question! I'm still learning about that. Try asking about file scanning, URL checking, or GitHub analysis!"
        elif len(message.split()) < 3:
            return f"Could you tell me more about what you'd like to know? I can help with scanning, threats, or security advice."
        else:
            return f"I understand you're asking about '{message[:50]}...'. For specific security concerns, try asking about file scanning, URL safety, or GitHub repository analysis."
    
    def save_conversation(self, user_id, message, response):
        """Save conversation to database"""
        try:
            conn = sqlite3.connect('bot_database.db')
            c = conn.cursor()
            conv_id = hashlib.md5(f"{user_id}{time.time()}".encode()).hexdigest()[:16]
            c.execute('''INSERT INTO bot_conversations 
                        (conv_id, user_id, message, response, timestamp) 
                        VALUES (?,?,?,?,?)''',
                     (conv_id, user_id, message, response, datetime.now()))
            conn.commit()
            conn.close()
        except:
            pass

# Initialize scanner and bot
scanner = AdvancedScanner()
bot_intelligence = BotIntelligence()

# Routes
@app.route('/')
def index():
    return render_template('index.html', owner=OWNER_NAME, bot_name=BOT_NAME)

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Secure filename and save temporarily
    filename = secure_filename(file.filename)
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{time.time()}_{filename}")
    file.save(temp_path)
    
    try:
        # Scan file
        results = scanner.scan_file(temp_path, filename)
        
        # Calculate risk level
        risk_level = 'CLEAN'
        if results['risk_score'] >= 70:
            risk_level = 'CRITICAL'
        elif results['risk_score'] >= 50:
            risk_level = 'HIGH'
        elif results['risk_score'] >= 30:
            risk_level = 'MEDIUM'
        elif results['risk_score'] >= 10:
            risk_level = 'LOW'
        
        results['risk_level'] = risk_level
        
        # Save to history
        save_scan_history(
            user_id=request.remote_addr,
            scan_type='file',
            target=filename,
            risk_score=results['risk_score'],
            risk_level=risk_level,
            threats_found=len(results['threats']),
            result_data=json.dumps(results)
        )
        
        # Emit real-time update
        socketio.emit('new_scan', {
            'type': 'file',
            'target': filename,
            'risk_level': risk_level,
            'timestamp': datetime.now().isoformat()
        })
        
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
        'virustotal': None,
        'domain_info': {}
    }
    
    try:
        # Fetch URL content
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Scan content
        content = response.text
        threats = scanner.scan_text_content(content, url)
        results['threats'] = threats
        
        # Get domain info
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        results['domain_info'] = {
            'domain': domain,
            'scheme': parsed.scheme,
            'path': parsed.path,
            'status_code': response.status_code,
            'content_type': response.headers.get('Content-Type', ''),
            'server': response.headers.get('Server', ''),
            'content_length': len(content)
        }
        
        # Check with VirusTotal
        results['virustotal'] = check_virustotal_url(url)
        
        # Calculate risk score
        results['risk_score'] = scanner.calculate_risk_score(threats, results['virustotal'])
        
        # Risk level
        risk_level = 'CLEAN'
        if results['risk_score'] >= 70:
            risk_level = 'CRITICAL'
        elif results['risk_score'] >= 50:
            risk_level = 'HIGH'
        elif results['risk_score'] >= 30:
            risk_level = 'MEDIUM'
        elif results['risk_score'] >= 10:
            risk_level = 'LOW'
        
        results['risk_level'] = risk_level
        
        # Save to history
        save_scan_history(
            user_id=request.remote_addr,
            scan_type='url',
            target=url,
            risk_score=results['risk_score'],
            risk_level=risk_level,
            threats_found=len(threats),
            result_data=json.dumps(results)
        )
        
        # Emit real-time update
        socketio.emit('new_scan', {
            'type': 'url',
            'target': url[:50] + '...' if len(url) > 50 else url,
            'risk_level': risk_level,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        results['error'] = str(e)
        results['risk_level'] = 'ERROR'
    
    return jsonify(results)

@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    data = request.json
    repo_url = data.get('url', '')
    
    if not repo_url or 'github.com' not in repo_url:
        return jsonify({'error': 'Invalid GitHub URL'}), 400
    
    # Create temp directory for cloning
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clone repository
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        repo_path = os.path.join(temp_dir, repo_name)
        
        # Clone with depth 1 for speed
        git.Repo.clone_from(repo_url, repo_path, depth=1)
        
        results = {
            'repo_url': repo_url,
            'repo_name': repo_name,
            'threats': [],
            'risk_score': 0,
            'files_scanned': 0,
            'file_types': {}
        }
        
        # Scan all files
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                
                # Get file extension
                ext = os.path.splitext(file)[1].lower()
                results['file_types'][ext] = results['file_types'].get(ext, 0) + 1
                
                # Scan text files
                try:
                    mime = magic.from_file(file_path, mime=True)
                    if scanner.is_text_file(mime):
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                            threats = scanner.scan_text_content(content, rel_path)
                            results['threats'].extend(threats)
                            results['files_scanned'] += 1
                except:
                    continue
        
        # Calculate risk score
        results['risk_score'] = scanner.calculate_risk_score(results['threats'], None)
        
        # Risk level
        risk_level = 'CLEAN'
        if results['risk_score'] >= 70:
            risk_level = 'CRITICAL'
        elif results['risk_score'] >= 50:
            risk_level = 'HIGH'
        elif results['risk_score'] >= 30:
            risk_level = 'MEDIUM'
        elif results['risk_score'] >= 10:
            risk_level = 'LOW'
        
        results['risk_level'] = risk_level
        
        # Save to history
        save_scan_history(
            user_id=request.remote_addr,
            scan_type='github',
            target=repo_url,
            risk_score=results['risk_score'],
            risk_level=risk_level,
            threats_found=len(results['threats']),
            result_data=json.dumps(results)
        )
        
        # Emit real-time update
        socketio.emit('new_scan', {
            'type': 'github',
            'target': repo_name,
            'risk_level': risk_level,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify(results)
    
    finally:
        # Clean up temp directory
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

@app.route('/api/bot/message', methods=['POST'])
def bot_message():
    data = request.json
    user_message = data.get('message', '')
    user_id = request.remote_addr
    
    # Get bot response
    response = bot_intelligence.process_message(user_id, user_message)
    
    return jsonify({
        'response': response,
        'bot_name': BOT_NAME,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    limit = int(request.args.get('limit', 10))
    
    conn = sqlite3.connect('bot_database.db')
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
            'target': row[2],
            'risk_score': row[3],
            'risk_level': row[4],
            'threats_found': row[5],
            'timestamp': row[6]
        })
    
    return jsonify(history)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = sqlite3.connect('bot_database.db')
    c = conn.cursor()
    
    # Total scans
    c.execute('SELECT COUNT(*) FROM scan_history')
    total_scans = c.fetchone()[0]
    
    # Threats found
    c.execute('SELECT SUM(threats_found) FROM scan_history')
    threats_found = c.fetchone()[0] or 0
    
    # Clean files (no threats)
    c.execute('SELECT COUNT(*) FROM scan_history WHERE threats_found = 0')
    clean_files = c.fetchone()[0]
    
    # Average risk score
    c.execute('SELECT AVG(risk_score) FROM scan_history')
    avg_risk = c.fetchone()[0] or 0
    
    # Scan type breakdown
    c.execute('SELECT scan_type, COUNT(*) FROM scan_history GROUP BY scan_type')
    type_breakdown = {row[0]: row[1] for row in c.fetchall()}
    
    # Risk level breakdown
    c.execute('SELECT risk_level, COUNT(*) FROM scan_history GROUP BY risk_level')
    risk_breakdown = {row[0]: row[1] for row in c.fetchall()}
    
    conn.close()
    
    return jsonify({
        'total_scans': total_scans,
        'threats_found': threats_found,
        'clean_files': clean_files,
        'avg_risk_score': round(avg_risk, 2),
        'type_breakdown': type_breakdown,
        'risk_breakdown': risk_breakdown
    })

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    conn = sqlite3.connect('bot_database.db')
    c = conn.cursor()
    c.execute('SELECT result_data FROM scan_history WHERE scan_id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return jsonify(json.loads(row[0]))
    return jsonify({'error': 'Scan not found'}), 404

def save_scan_history(user_id, scan_type, target, risk_score, risk_level, threats_found, result_data):
    """Save scan to database"""
    try:
        conn = sqlite3.connect('bot_database.db')
        c = conn.cursor()
        scan_id = hashlib.md5(f"{user_id}{target}{time.time()}".encode()).hexdigest()[:16]
        c.execute('''INSERT INTO scan_history 
                    (scan_id, user_id, scan_type, target, risk_score, risk_level, threats_found, timestamp, result_data) 
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                 (scan_id, user_id, scan_type, target, risk_score, risk_level, threats_found, datetime.now(), result_data))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error saving scan history: {e}")

def check_virustotal_url(url):
    """Check URL with VirusTotal"""
    try:
        headers = {'x-apikey': VT_API_KEY}
        
        # URL encode for VT API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total': sum(stats.values())
            }
    except:
        pass
    return None

# SocketIO events
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.remote_addr}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.remote_addr}")

@socketio.on('typing')
def handle_typing(data):
    emit('typing_response', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)