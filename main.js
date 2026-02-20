// ============================================
// Adixtpy Security Scanner - Main JavaScript
// Created by Adixtpy
// ============================================

// Initialize Socket.IO
const socket = io();

// Global variables
let currentMode = 'file';
let scanHistory = [];
let selectedFile = null;
let botTyping = false;
let scanInProgress = false;

// Matrix Rain Effect
const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const matrix = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()*&^%+-/~{[|`]}";
const matrixArray = matrix.split("");

const fontSize = 14;
const columns = canvas.width / fontSize;

const drops = [];
for(let x = 0; x < columns; x++) {
    drops[x] = 1;
}

function drawMatrix() {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.04)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    ctx.fillStyle = '#0f0';
    ctx.font = fontSize + 'px monospace';
    
    for(let i = 0; i < drops.length; i++) {
        const text = matrixArray[Math.floor(Math.random() * matrixArray.length)];
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);
        
        if(drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }
        drops[i]++;
    }
}

setInterval(drawMatrix, 35);

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadStats();
    loadHistory();
    setupEventListeners();
    initializeBot();
    startRealTimeUpdates();
});

// Setup event listeners
function setupEventListeners() {
    // File upload drag and drop
    const uploadContainer = document.getElementById('uploadContainer');
    const fileInput = document.getElementById('fileInput');
    
    uploadContainer.addEventListener('click', () => fileInput.click());
    uploadContainer.addEventListener('dragover', handleDragOver);
    uploadContainer.addEventListener('dragleave', handleDragLeave);
    uploadContainer.addEventListener('drop', handleDrop);
    
    fileInput.addEventListener('change', handleFileSelect);
    
    // Bot input
    const botInput = document.getElementById('botInput');
    botInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendBotMessage();
        }
    });
    
    botInput.addEventListener('input', function() {
        if (!botTyping) {
            botTyping = true;
            socket.emit('typing', { user: 'user', typing: true });
            
            setTimeout(() => {
                botTyping = false;
                socket.emit('typing', { user: 'user', typing: false });
            }, 1000);
        }
    });
    
    // Window resize
    window.addEventListener('resize', function() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// Handle drag over
function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    document.getElementById('uploadContainer').classList.add('drag-over');
}

// Handle drag leave
function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    document.getElementById('uploadContainer').classList.remove('drag-over');
}

// Handle drop
function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    
    const uploadContainer = document.getElementById('uploadContainer');
    uploadContainer.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFiles(files[0]);
    }
}

// Handle file select
function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        handleFiles(files[0]);
    }
}

// Handle files
function handleFiles(file) {
    selectedFile = file;
    
    const fileInfo = document.getElementById('selectedFileInfo');
    const fileName = fileInfo.querySelector('.file-name');
    const fileSize = fileInfo.querySelector('.file-size');
    
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    
    fileInfo.style.display = 'flex';
    
    showToast('File selected', `Ready to scan: ${file.name}`, 'info');
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Remove selected file
function removeSelectedFile() {
    selectedFile = null;
    document.getElementById('fileInput').value = '';
    document.getElementById('selectedFileInfo').style.display = 'none';
}

// Set scan mode
function setScanMode(mode) {
    currentMode = mode;
    
    // Update active button
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-mode="${mode}"]`).classList.add('active');
    
    // Show appropriate scan area
    document.getElementById('fileScanArea').style.display = mode === 'file' ? 'block' : 'none';
    document.getElementById('urlScanArea').style.display = mode === 'url' ? 'block' : 'none';
    document.getElementById('githubScanArea').style.display = mode === 'github' ? 'block' : 'none';
}

// Set URL example
function setUrlExample(url) {
    document.getElementById('urlInput').value = url;
}

// Set GitHub example
function setGitHubExample(url) {
    document.getElementById('githubInput').value = url;
}

// Start scan
async function startScan() {
    if (scanInProgress) {
        showToast('Scan in progress', 'Please wait for current scan to complete', 'warning');
        return;
    }
    
    const scanBtn = document.getElementById('scanBtn');
    const btnText = scanBtn.querySelector('.btn-text');
    const btnLoader = scanBtn.querySelector('.btn-loader');
    
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline-block';
    scanBtn.disabled = true;
    scanInProgress = true;
    
    try {
        let result;
        
        switch(currentMode) {
            case 'file':
                result = await scanFile();
                break;
            case 'url':
                result = await scanUrl();
                break;
            case 'github':
                result = await scanGithub();
                break;
        }
        
        displayResults(result);
        addToHistory(result);
        loadStats();
        
        // Notify bot
        addBotMessage(`Scan complete! Risk level: ${result.risk_level}`, 'bot');
        
        showToast('Scan Complete', `Risk level: ${result.risk_level}`, getToastType(result.risk_level));
        
    } catch (error) {
        console.error('Scan error:', error);
        showToast('Scan Failed', error.message || 'An error occurred during scan', 'error');
        
        addBotMessage(`Sorry, the scan failed: ${error.message}`, 'bot');
    } finally {
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
        scanBtn.disabled = false;
        scanInProgress = false;
    }
}

// Scan file
async function scanFile() {
    if (!selectedFile) {
        throw new Error('Please select a file to scan');
    }
    
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    // Show upload progress
    const progressBar = document.querySelector('.progress-bar');
    progressBar.style.width = '0%';
    
    const response = await fetch('/api/scan/file', {
        method: 'POST',
        body: formData,
        onUploadProgress: (progressEvent) => {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            progressBar.style.width = percentCompleted + '%';
        }
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Scan failed');
    }
    
    return await response.json();
}

// Scan URL
async function scanUrl() {
    const url = document.getElementById('urlInput').value.trim();
    
    if (!url) {
        throw new Error('Please enter a URL to scan');
    }
    
    const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Scan failed');
    }
    
    return await response.json();
}

// Scan GitHub
async function scanGithub() {
    const url = document.getElementById('githubInput').value.trim();
    
    if (!url) {
        throw new Error('Please enter a GitHub URL to scan');
    }
    
    if (!url.includes('github.com')) {
        throw new Error('Invalid GitHub URL');
    }
    
    const response = await fetch('/api/scan/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Scan failed');
    }
    
    return await response.json();
}

// Display results
function displayResults(result) {
    const resultsPanel = document.getElementById('resultsPanel');
    const riskFill = document.getElementById('riskFill');
    const scanId = document.getElementById('scanId');
    const fileInfoPanel = document.getElementById('fileInfoPanel');
    const threatsList = document.getElementById('threatsList');
    const threatCount = document.getElementById('threatCount');
    const vtSection = document.getElementById('vtSection');
    const vtResults = document.getElementById('vtResults');
    
    // Update risk meter
    riskFill.style.width = result.risk_score + '%';
    
    // Set scan ID
    scanId.textContent = `ID: ${result.id || 'N/A'}`;
    
    // Display file information
    let fileInfoHtml = '';
    
    if (result.file_info) {
        fileInfoHtml = `
            <div class="info-item">
                <span class="info-label">Filename</span>
                <span class="info-value">${result.file_info.name}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Size</span>
                <span class="info-value">${formatFileSize(result.file_info.size)}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Type</span>
                <span class="info-value">${result.file_info.mime_type || 'Unknown'}</span>
            </div>
            <div class="info-item">
                <span class="info-label">SHA256</span>
                <span class="info-value hash">${result.hashes?.sha256 || 'N/A'}</span>
            </div>
        `;
    } else if (result.url) {
        fileInfoHtml = `
            <div class="info-item">
                <span class="info-label">URL</span>
                <span class="info-value">${result.url}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Status</span>
                <span class="info-value">${result.domain_info?.status_code || 'N/A'}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Server</span>
                <span class="info-value">${result.domain_info?.server || 'N/A'}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Content Length</span>
                <span class="info-value">${formatFileSize(result.domain_info?.content_length || 0)}</span>
            </div>
        `;
    } else if (result.repo_url) {
        fileInfoHtml = `
            <div class="info-item">
                <span class="info-label">Repository</span>
                <span class="info-value">${result.repo_name}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Files Scanned</span>
                <span class="info-value">${result.files_scanned || 0}</span>
            </div>
            <div class="info-item">
                <span class="info-label">File Types</span>
                <span class="info-value">${Object.keys(result.file_types || {}).length}</span>
            </div>
        `;
    }
    
    fileInfoPanel.innerHTML = fileInfoHtml;
    
    // Display threats
    threatCount.textContent = result.threats?.length || 0;
    
    if (result.threats && result.threats.length > 0) {
        let threatsHtml = '';
        
        result.threats.forEach((threat, index) => {
            threatsHtml += `
                <div class="threat-item" data-severity="${threat.severity}" style="animation-delay: ${index * 0.1}s">
                    <div class="threat-header">
                        <span class="threat-category">${threat.category}</span>
                        <span class="threat-severity" data-severity="${threat.severity}">${threat.severity}</span>
                    </div>
                    <div class="threat-description">${threat.description}</div>
                    <div class="threat-match">${threat.match}</div>
                    <div class="threat-line">Line: ${threat.line}</div>
                </div>
            `;
        });
        
        threatsList.innerHTML = threatsHtml;
    } else {
        threatsList.innerHTML = '<div class="no-threats">✅ No threats detected</div>';
    }
    
    // Display VirusTotal results
    if (result.virustotal) {
        vtSection.style.display = 'block';
        vtResults.innerHTML = `
            <div class="vt-stat">
                <div class="vt-label">Malicious</div>
                <div class="vt-value malicious">${result.virustotal.malicious}</div>
            </div>
            <div class="vt-stat">
                <div class="vt-label">Suspicious</div>
                <div class="vt-value suspicious">${result.virustotal.suspicious}</div>
            </div>
            <div class="vt-stat">
                <div class="vt-label">Harmless</div>
                <div class="vt-value harmless">${result.virustotal.harmless}</div>
            </div>
            <div class="vt-stat">
                <div class="vt-label">Undetected</div>
                <div class="vt-value undetected">${result.virustotal.undetected}</div>
            </div>
        `;
    } else {
        vtSection.style.display = 'none';
    }
    
    // Show results panel
    resultsPanel.style.display = 'block';
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Get toast type from risk level
function getToastType(riskLevel) {
    switch(riskLevel) {
        case 'CRITICAL':
        case 'HIGH':
            return 'error';
        case 'MEDIUM':
            return 'warning';
        case 'LOW':
            return 'info';
        default:
            return 'success';
    }
}

// Add to history
function addToHistory(result) {
    const historyItem = {
        id: result.id || Date.now().toString(),
        type: currentMode,
        target: result.file_info?.name || result.url || result.repo_name || 'Unknown',
        risk_score: result.risk_score,
        risk_level: result.risk_level,
        threats_found: result.threats?.length || 0,
        timestamp: new Date().toISOString()
    };
    
    scanHistory.unshift(historyItem);
    if (scanHistory.length > 20) scanHistory.pop();
    
    renderHistory();
}

// Render history
function renderHistory(filter = 'all') {
    const grid = document.getElementById('historyGrid');
    
    const filtered = filter === 'all' 
        ? scanHistory 
        : scanHistory.filter(item => item.type === filter);
    
    if (filtered.length === 0) {
        grid.innerHTML = '<div class="no-history">No scans yet</div>';
        return;
    }
    
    grid.innerHTML = filtered.map(item => `
        <div class="history-card" data-risk="${item.risk_level}" onclick="viewScanDetails('${item.id}')">
            <div class="history-header">
                <span class="history-type">${item.type.toUpperCase()}</span>
                <span class="history-risk" data-risk="${item.risk_level}">${item.risk_level}</span>
            </div>
            <div class="history-title">${item.target}</div>
            <div class="history-stats">
                <span>Risk: ${item.risk_score}%</span>
                <span>Threats: ${item.threats_found}</span>
            </div>
            <div class="history-time">${formatTime(item.timestamp)}</div>
        </div>
    `).join('');
}

// Format time
function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
}

// Filter history
function filterHistory(filter) {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    renderHistory(filter);
}

// View scan details
async function viewScanDetails(id) {
    try {
        const response = await fetch(`/api/scan/${id}`);
        if (response.ok) {
            const result = await response.json();
            displayResults(result);
        }
    } catch (error) {
        console.error('Failed to load scan details:', error);
    }
}

// Load stats
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            const stats = await response.json();
            
            document.getElementById('totalScans').textContent = stats.total_scans;
            document.getElementById('threatsFound').textContent = stats.threats_found;
            document.getElementById('cleanFiles').textContent = stats.clean_files;
            document.getElementById('avgRisk').textContent = stats.avg_risk_score + '%';
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Load history
async function loadHistory() {
    try {
        const response = await fetch('/api/history?limit=20');
        if (response.ok) {
            scanHistory = await response.json();
            renderHistory();
        }
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

// Initialize bot
function initializeBot() {
    addBotMessage("Hello! I'm Aditya, your AI security assistant. I can help you scan files, check URLs, and analyze GitHub repositories. What would you like to do?", 'bot');
}

// Send bot message
async function sendBotMessage() {
    const input = document.getElementById('botInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    addBotMessage(message, 'user');
    input.value = '';
    
    // Show typing indicator
    const typingIndicator = document.createElement('div');
    typingIndicator.className = 'message bot-message typing';
    typingIndicator.innerHTML = `
        <div class="message-avatar">🤖</div>
        <div class="message-content">
            <div class="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
            </div>
        </div>
    `;
    document.getElementById('botMessages').appendChild(typingIndicator);
    
    try {
        const response = await fetch('/api/bot/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        
        // Remove typing indicator
        typingIndicator.remove();
        
        if (response.ok) {
            const data = await response.json();
            addBotMessage(data.response, 'bot');
            
            // Handle special commands
            if (message.toLowerCase().includes('file')) {
                setScanMode('file');
            } else if (message.toLowerCase().includes('url')) {
                setScanMode('url');
            } else if (message.toLowerCase().includes('github')) {
                setScanMode('github');
            }
        }
    } catch (error) {
        typingIndicator.remove();
        addBotMessage("Sorry, I'm having trouble connecting. Please try again.", 'bot');
    }
}

// Add bot message
function addBotMessage(message, sender) {
    const messagesDiv = document.getElementById('botMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${sender}-message`;
    
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    messageDiv.innerHTML = `
        <div class="message-avatar">${sender === 'bot' ? '🤖' : '👤'}</div>
        <div class="message-content">
            <div class="message-sender">${sender === 'bot' ? 'Aditya' : 'You'}</div>
            <div class="message-text">${message}</div>
            <div class="message-time">${time}</div>
        </div>
    `;
    
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Ask bot with suggestion
function askBot(message) {
    document.getElementById('botInput').value = message;
    sendBotMessage();
}

// Clear bot chat
function clearBotChat() {
    const messagesDiv = document.getElementById('botMessages');
    messagesDiv.innerHTML = '';
    initializeBot();
}

// Download report
function downloadReport() {
    const results = document.getElementById('resultsPanel');
    const scanId = document.getElementById('scanId').textContent.replace('ID: ', '');
    
    // Create report content
    const report = {
        scan_id: scanId,
        timestamp: new Date().toISOString(),
        results: results.innerText
    };
    
    // Create and download file
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-report-${scanId}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    showToast('Report Downloaded', 'Scan report has been downloaded', 'success');
}

// Share results
function shareResults() {
    const scanId = document.getElementById('scanId').textContent.replace('ID: ', '');
    const shareData = {
        title: 'Security Scan Results',
        text: `Check out this security scan result: ${window.location.origin}/scan/${scanId}`,
        url: window.location.href
    };
    
    if (navigator.share) {
        navigator.share(shareData)
            .then(() => showToast('Shared', 'Results shared successfully', 'success'))
            .catch(() => showToast('Share Failed', 'Could not share results', 'error'));
    } else {
        navigator.clipboard.writeText(shareData.url)
            .then(() => showToast('Copied', 'Link copied to clipboard', 'success'))
            .catch(() => showToast('Copy Failed', 'Could not copy link', 'error'));
    }
}

// Show toast notification
function showToast(title, message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <div class="toast-icon">${icons[type]}</div>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
        <div class="toast-close" onclick="this.parentElement.remove()">✕</div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// Show about modal
function showAbout() {
    document.getElementById('modalTitle').textContent = 'About Adixtpy Security';
    document.getElementById('modalBody').innerHTML = `
        <p>Adixtpy Security Scanner is an advanced threat detection platform created by Adixtpy.</p>
        <br>
        <h4>Features:</h4>
        <ul>
            <li>🔍 Multi-engine file scanning</li>
            <li>🌐 URL safety analysis</li>
            <li>🐙 GitHub repository auditing</li>
            <li>🤖 AI-powered security assistant</li>
            <li>📊 Real-time threat intelligence</li>
        </ul>
        <br>
        <p>Version 2.0 | © 2024 Adixtpy</p>
    `;
    document.getElementById('modal').classList.add('active');
}

// Show privacy modal
function showPrivacy() {
    document.getElementById('modalTitle').textContent = 'Privacy Policy';
    document.getElementById('modalBody').innerHTML = `
        <p>Your privacy is important to us. Here's how we handle your data:</p>
        <br>
        <ul>
            <li>🔒 Files are scanned temporarily and not stored</li>
            <li>📝 Scan results are anonymized</li>
            <li>🚫 No personal data is collected</li>
            <li>🗑️ Automatic data cleanup after 24 hours</li>
        </ul>
    `;
    document.getElementById('modal').classList.add('active');
}

// Show terms modal
function showTerms() {
    document.getElementById('modalTitle').textContent = 'Terms of Service';
    document.getElementById('modalBody').innerHTML = `
        <p>By using this service, you agree to:</p>
        <br>
        <ul>
            <li>✅ Use the service for legitimate security purposes only</li>
            <li>❌ Not upload malicious content intentionally</li>
            <li>📊 Accept that scan results are provided "as is"</li>
            <li>🔐 Respect intellectual property rights</li>
        </ul>
    `;
    document.getElementById('modal').classList.add('active');
}

// Close modal
function closeModal() {
    document.getElementById('modal').classList.remove('active');
}

// Start real-time updates
function startRealTimeUpdates() {
    // Update stats every 30 seconds
    setInterval(loadStats, 30000);
    
    // Socket.IO events
    socket.on('connect', () => {
        console.log('Connected to real-time server');
    });
    
    socket.on('new_scan', (data) => {
        // Add to history in real-time
        scanHistory.unshift({
            id: Date.now().toString(),
            type: data.type,
            target: data.target,
            risk_level: data.risk_level,
            timestamp: data.timestamp
        });
        
        if (scanHistory.length > 20) scanHistory.pop();
        renderHistory();
    });
    
    socket.on('typing_response', (data) => {
        // Handle typing indicator
        console.log('User typing:', data);
    });
}

// Export functions for global use
window.setScanMode = setScanMode;
window.setUrlExample = setUrlExample;
window.setGitHubExample = setGitHubExample;
window.startScan = startScan;
window.removeSelectedFile = removeSelectedFile;
window.filterHistory = filterHistory;
window.viewScanDetails = viewScanDetails;
window.sendBotMessage = sendBotMessage;
window.askBot = askBot;
window.clearBotChat = clearBotChat;
window.downloadReport = downloadReport;
window.shareResults = shareResults;
window.showAbout = showAbout;
window.showPrivacy = showPrivacy;
window.showTerms = showTerms;
window.closeModal = closeModal;