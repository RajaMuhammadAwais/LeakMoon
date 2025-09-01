// LeakMon Web Interface JavaScript

class LeakMonApp {
    constructor() {
        this.socket = null;
        this.isMonitoring = false;
        this.detections = [];
        this.charts = {};
        
        this.init();
    }
    
    init() {
        this.initializeSocket();
        this.bindEvents();
        this.initializeCharts();
        this.loadInitialData();
        
        // Set default path to current directory
        document.getElementById('watch-paths').value = '.';
    }
    
    initializeSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to LeakMon server');
            this.showToast('Connected to LeakMon server', 'success');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from LeakMon server');
            this.showToast('Disconnected from server', 'warning');
        });
        
        this.socket.on('status', (data) => {
            this.updateStatus(data.is_monitoring);
            this.updateStats();
        });
        
        this.socket.on('new_detection', (data) => {
            this.handleNewDetection(data);
        });
    }
    
    bindEvents() {
        // Control buttons
        document.getElementById('start-btn').addEventListener('click', () => this.startMonitoring());
        document.getElementById('stop-btn').addEventListener('click', () => this.stopMonitoring());
        document.getElementById('scan-btn').addEventListener('click', () => this.scanNow());
        document.getElementById('clear-btn').addEventListener('click', () => this.clearDetections());
        document.getElementById('export-btn').addEventListener('click', () => this.exportDetections());
        
        // Enter key in path input
        document.getElementById('watch-paths').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.startMonitoring();
            }
        });
    }
    
    async loadInitialData() {
        try {
            // Load status
            const statusResponse = await fetch('/api/status');
            const statusData = await statusResponse.json();
            this.updateStatus(statusData.is_monitoring);
            
            // Load existing detections
            const detectionsResponse = await fetch('/api/detections');
            const detectionsData = await detectionsResponse.json();
            this.detections = detectionsData.detections || [];
            this.renderDetections();
            this.updateStats();
            this.updateCharts();
            
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showToast('Error loading initial data', 'error');
        }
    }
    
    async startMonitoring() {
        const pathsInput = document.getElementById('watch-paths').value.trim();
        const paths = pathsInput ? pathsInput.split(',').map(p => p.trim()) : ['.'];
        
        try {
            const response = await fetch('/api/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ paths: paths })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.showToast(`Monitoring started for: ${data.paths.join(', ')}`, 'success');
                this.updateStatus(true);
            } else {
                this.showToast(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            console.error('Error starting monitoring:', error);
            this.showToast('Error starting monitoring', 'error');
        }
    }
    
    async stopMonitoring() {
        try {
            const response = await fetch('/api/stop', {
                method: 'POST'
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.showToast('Monitoring stopped', 'info');
                this.updateStatus(false);
            } else {
                this.showToast(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            console.error('Error stopping monitoring:', error);
            this.showToast('Error stopping monitoring', 'error');
        }
    }
    
    async scanNow() {
        this.showToast('Scan feature will be implemented in CLI mode', 'info');
    }
    
    updateStatus(isMonitoring) {
        this.isMonitoring = isMonitoring;
        
        const statusBadge = document.getElementById('status-badge');
        const statusText = document.getElementById('status-text');
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        
        if (isMonitoring) {
            statusBadge.className = 'status-badge running';
            statusText.textContent = 'Monitoring';
            startBtn.disabled = true;
            stopBtn.disabled = false;
        } else {
            statusBadge.className = 'status-badge stopped';
            statusText.textContent = 'Stopped';
            startBtn.disabled = false;
            stopBtn.disabled = true;
        }
    }
    
    handleNewDetection(data) {
        // Add new detections to the beginning of the array
        const newDetections = data.detections.map(detection => ({
            ...detection,
            filepath: data.filepath
        }));
        
        this.detections.unshift(...newDetections);
        
        // Keep only last 100 detections
        if (this.detections.length > 100) {
            this.detections = this.detections.slice(0, 100);
        }
        
        this.renderDetections();
        this.updateStats();
        this.updateCharts();
        
        // Show notification for high severity detections
        const highSeverityDetections = newDetections.filter(d => d.severity === 'high');
        if (highSeverityDetections.length > 0) {
            this.showToast(`🚨 ${highSeverityDetections.length} high severity secret(s) detected!`, 'error');
        }
    }
    
    renderDetections() {
        const detectionsList = document.getElementById('detections-list');
        
        if (this.detections.length === 0) {
            detectionsList.innerHTML = `
                <div class="no-detections">
                    <i class="fas fa-shield-check"></i>
                    <p>No secrets detected yet. Start monitoring to begin scanning.</p>
                </div>
            `;
            return;
        }
        
        detectionsList.innerHTML = this.detections.map(detection => this.renderDetectionItem(detection)).join('');
    }
    
    renderDetectionItem(detection) {
        const timestamp = new Date(detection.timestamp).toLocaleString();
        const confidencePercent = Math.round(detection.confidence * 100);
        
        return `
            <div class="detection-item ${detection.severity}">
                <div class="detection-header">
                    <span class="detection-type ${detection.severity}">
                        <i class="fas fa-${this.getSeverityIcon(detection.severity)}"></i>
                        ${detection.type.replace(/_/g, ' ').toUpperCase()}
                    </span>
                    <span class="detection-time">${timestamp}</span>
                </div>
                <div class="detection-details">
                    <div class="detection-file">
                        <i class="fas fa-file-code"></i> ${detection.filepath}:${detection.line_number}
                    </div>
                    <div class="detection-context">${this.escapeHtml(detection.context)}</div>
                    <div class="detection-meta">
                        <span><i class="fas fa-percentage"></i> Confidence: ${confidencePercent}%</span>
                        <span><i class="fas fa-eye"></i> Preview: ${this.escapeHtml(detection.value_preview)}</span>
                    </div>
                </div>
            </div>
        `;
    }
    
    getSeverityIcon(severity) {
        switch (severity) {
            case 'high': return 'exclamation-triangle';
            case 'medium': return 'exclamation-circle';
            case 'low': return 'info-circle';
            default: return 'question-circle';
        }
    }
    
    updateStats() {
        const stats = this.calculateStats();
        
        document.getElementById('high-severity-count').textContent = stats.high;
        document.getElementById('medium-severity-count').textContent = stats.medium;
        document.getElementById('low-severity-count').textContent = stats.low;
        document.getElementById('total-detections').textContent = stats.total;
    }
    
    calculateStats() {
        const stats = { high: 0, medium: 0, low: 0, total: 0 };
        
        this.detections.forEach(detection => {
            stats[detection.severity]++;
            stats.total++;
        });
        
        return stats;
    }
    
    initializeCharts() {
        // Detection Types Chart
        const typesCtx = document.getElementById('types-chart').getContext('2d');
        this.charts.types = new Chart(typesCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#ef4444', '#f59e0b', '#06b6d4', '#10b981', '#8b5cf6',
                        '#f97316', '#ec4899', '#14b8a6', '#f43f5e', '#84cc16'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severity-chart').getContext('2d');
        this.charts.severity = new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Detections',
                    data: [0, 0, 0],
                    backgroundColor: ['#ef4444', '#f59e0b', '#06b6d4']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
    
    updateCharts() {
        // Update types chart
        const typesCounts = {};
        this.detections.forEach(detection => {
            const type = detection.type.replace(/_/g, ' ').toUpperCase();
            typesCounts[type] = (typesCounts[type] || 0) + 1;
        });
        
        this.charts.types.data.labels = Object.keys(typesCounts);
        this.charts.types.data.datasets[0].data = Object.values(typesCounts);
        this.charts.types.update();
        
        // Update severity chart
        const stats = this.calculateStats();
        this.charts.severity.data.datasets[0].data = [stats.high, stats.medium, stats.low];
        this.charts.severity.update();
    }
    
    clearDetections() {
        if (confirm('Are you sure you want to clear all detections from the display?')) {
            this.detections = [];
            this.renderDetections();
            this.updateStats();
            this.updateCharts();
            this.showToast('Detections cleared from display', 'info');
        }
    }
    
    exportDetections() {
        if (this.detections.length === 0) {
            this.showToast('No detections to export', 'warning');
            return;
        }
        
        const dataStr = JSON.stringify(this.detections, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `leakmon-detections-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        this.showToast('Detections exported successfully', 'success');
    }
    
    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-${this.getToastIcon(type)}"></i>
                <span>${message}</span>
            </div>
        `;
        
        toastContainer.appendChild(toast);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 5000);
        
        // Click to dismiss
        toast.addEventListener('click', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }
    
    getToastIcon(type) {
        switch (type) {
            case 'success': return 'check-circle';
            case 'error': return 'exclamation-triangle';
            case 'warning': return 'exclamation-circle';
            case 'info': return 'info-circle';
            default: return 'info-circle';
        }
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new LeakMonApp();
});

