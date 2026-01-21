import os
import socket
import subprocess
import threading
import time
import struct
import random
import re
import json
from datetime import datetime
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

app = Flask(__name__)

# Embedded HTML template
HTML_TEMPLATE = """
<! DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deep Network Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family:  -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            background:  #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .header p {
            opacity: 0.9;
            font-size: 1.1rem;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        . scan-panel {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .input-row {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            align-items: center;
            flex-wrap: wrap;
        }

        .input-group {
            flex: 1;
            min-width: 250px;
        }

        . input-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #555;
        }

        input[type="text"], select {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e0e0e0;
            border-radius:  6px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }

        input[type="text"]:focus, select: focus {
            outline: none;
            border-color: #667eea;
        }

        .scan-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        . checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .checkbox-group input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }

        .checkbox-group label {
            cursor: pointer;
            user-select: none;
        }

        .btn {
            padding: 0.875rem 2rem;
            font-size: 1rem;
            font-weight: 600;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .progress-section {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            display: none;
        }

        .progress-section.active {
            display: block;
        }

        .progress-bar {
            width: 100%;
            height:  8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 1rem;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%;
            transition:  width 0.3s;
        }

        .results-section {
            display: none;
        }

        .results-section. active {
            display: block;
        }

        .results-header {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom:  2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }

        .stat-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
        }

        .stat-card. success {
            background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
        }

        .stat-card.warning {
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
        }

        .stat-label {
            font-size: 0.9rem;
            color: #555;
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: #2c3e50;
        }

        .os-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: #667eea;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            margin-top: 0.5rem;
        }

        .table-container {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            overflow-x: auto;
        }

        .table-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .table-title {
            font-size: 1.5rem;
            font-weight:  600;
            color: #2c3e50;
        }

        .filter-group {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .filter-group select {
            padding: 0.5rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead {
            background: #f8f9fa;
        }

        th {
            padding: 1rem;
            text-align:  left;
            font-weight:  600;
            color: #555;
            border-bottom: 2px solid #e0e0e0;
            cursor: pointer;
            user-select: none;
        }

        th:hover {
            background: #e9ecef;
        }

        td {
            padding: 1rem;
            border-bottom: 1px solid #f0f0f0;
        }

        tbody tr:hover {
            background:  #f8f9fa;
        }

        .port-badge {
            background: #667eea;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            display: inline-block;
        }

        .protocol-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.85rem;
        }

        .protocol-tcp {
            background: #e3f2fd;
            color:  #1976d2;
        }

        .protocol-udp {
            background: #f3e5f5;
            color: #7b1fa2;
        }

        .state-open {
            color: #2e7d32;
            font-weight: 600;
        }

        .state-closed {
            color: #c62828;
            font-weight: 600;
        }

        .state-filtered {
            color: #f57c00;
            font-weight: 600;
        }

        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: #999;
        }

        .empty-state-icon {
            font-size:  4rem;
            margin-bottom:  1rem;
        }

        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width:  20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .scan-params {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 2rem;
        }

        . scan-params h3 {
            margin-bottom: 1rem;
            color: #2c3e50;
        }

        .param-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .param-item {
            display: flex;
            justify-content: space-between;
        }

        .param-label {
            color: #666;
        }

        .param-value {
            font-weight: 600;
            color: #2c3e50;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .input-row {
                flex-direction: column;
            }

            .results-grid {
                grid-template-columns: 1fr;
            }

            table {
                font-size: 0.9rem;
            }

            th, td {
                padding: 0.75rem 0.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🔍 Deep Network Scanner</h1>
            <p>Comprehensive TCP & UDP port scanning with service detection and OS fingerprinting</p>
        </div>
    </div>

    <div class="container">
        <div class="scan-panel">
            <div class="input-row">
                <div class="input-group">
                    <label for="targetInput">Target Host</label>
                    <input type="text" id="targetInput" placeholder="IP address or hostname (e.g., 192.168.1.1)">
                </div>
                <div class="input-group">
                    <label for="portRange">Port Range</label>
                    <select id="portRange">
                        <option value="top100">Top 100 Ports (Fast)</option>
                        <option value="top1000">Top 1000 Ports</option>
                        <option value="all">All Ports 1-65535 (Slow)</option>
                        <option value="custom">Custom Range</option>
                    </select>
                </div>
            </div>

            <div class="input-row" id="customPortRow" style="display: none;">
                <div class="input-group">
                    <label for="startPort">Start Port</label>
                    <input type="text" id="startPort" placeholder="1" value="1">
                </div>
                <div class="input-group">
                    <label for="endPort">End Port</label>
                    <input type="text" id="endPort" placeholder="1000" value="1000">
                </div>
            </div>

            <div class="scan-options">
                <div class="checkbox-group">
                    <input type="checkbox" id="scanTCP" checked>
                    <label for="scanTCP">TCP Scan</label>
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="scanUDP" checked>
                    <label for="scanUDP">UDP Scan</label>
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="detectService" checked>
                    <label for="detectService">Service Detection</label>
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="detectOS" checked>
                    <label for="detectOS">OS Detection</label>
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="checkAlive" checked>
                    <label for="checkAlive">Check if Alive</label>
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="traceroute">
                    <label for="traceroute">Traceroute</label>
                </div>
            </div>

            <button class="btn btn-primary" id="scanBtn" onclick="startScan()">
                <span>🚀 Start Deep Scan</span>
            </button>
        </div>

        <div class="progress-section" id="progressSection">
            <div style="display: flex; align-items: center; gap: 1rem;">
                <div class="spinner"></div>
                <div>
                    <strong>Scanning in progress...</strong>
                    <p id="progressText" style="color: #666; margin-top: 0.25rem;">Initializing... </p>
                </div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
        </div>

        <div class="results-section" id="resultsSection">
            <div class="results-header">
                <h2>Results</h2>
                <div class="results-grid">
                    <div class="stat-card">
                        <div class="stat-label">Host</div>
                        <div class="stat-value" id="hostIP" style="font-size: 1.2rem;">-</div>
                        <div id="hostname" style="color: #666; margin-top: 0.5rem;">-</div>
                        <div id="osInfo"></div>
                    </div>
                    <div class="stat-card success">
                        <div class="stat-label">Open Ports</div>
                        <div class="stat-value" id="openPorts">0</div>
                    </div>
                    <div class="stat-card warning">
                        <div class="stat-label">Filtered Ports</div>
                        <div class="stat-value" id="filteredPorts">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Scan Duration</div>
                        <div class="stat-value" id="scanDuration" style="font-size: 1.5rem;">-</div>
                    </div>
                </div>
            </div>

            <div class="table-container">
                <div class="table-header">
                    <h3 class="table-title">Ports</h3>
                    <div class="filter-group">
                        <label>Sort by:</label>
                        <select id="sortBy" onchange="sortTable()">
                            <option value="port">Port Number</option>
                            <option value="protocol">Protocol</option>
                            <option value="state">State</option>
                            <option value="service">Service</option>
                        </select>
                        <select id="sortOrder" onchange="sortTable()">
                            <option value="asc">Ascending</option>
                            <option value="desc">Descending</option>
                        </select>
                    </div>
                </div>

                <table id="portsTable">
                    <thead>
                        <tr>
                            <th onclick="sortTableByColumn(0)">Port</th>
                            <th onclick="sortTableByColumn(1)">Protocol</th>
                            <th onclick="sortTableByColumn(2)">State</th>
                            <th onclick="sortTableByColumn(3)">Service</th>
                            <th onclick="sortTableByColumn(4)">Product</th>
                            <th onclick="sortTableByColumn(5)">Version</th>
                            <th onclick="sortTableByColumn(6)">Details</th>
                        </tr>
                    </thead>
                    <tbody id="portsTableBody">
                    </tbody>
                </table>
            </div>

            <div class="scan-params">
                <h3>Scan Parameters</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <span class="param-label">Host:</span>
                        <span class="param-value" id="paramHost">-</span>
                    </div>
                    <div class="param-item">
                        <span class="param-label">Protocol:</span>
                        <span class="param-value" id="paramProtocol">-</span>
                    </div>
                    <div class="param-item">
                        <span class="param-label">Scan Type:</span>
                        <span class="param-value" id="paramScanType">-</span>
                    </div>
                    <div class="param-item">
                        <span class="param-label">Ports:</span>
                        <span class="param-value" id="paramPorts">-</span>
                    </div>
                    <div class="param-item">
                        <span class="param-label">Check Alive:</span>
                        <span class="param-value" id="paramAlive">-</span>
                    </div>
                    <div class="param-item">
                        <span class="param-label">Service Detection:</span>
                        <span class="param-value" id="paramService">-</span>
                    </div>
                    <div class="param-item">
                        <span class="param-label">OS Detection:</span>
                        <span class="param-value" id="paramOS">-</span>
                    </div>
                    <div class="param-item">
                        <span class="param-label">Traceroute:</span>
                        <span class="param-value" id="paramTrace">-</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="empty-state" id="emptyState">
            <div class="empty-state-icon">🎯</div>
            <h2>Ready to Scan</h2>
            <p>Configure your scan parameters above and click "Start Deep Scan"</p>
        </div>
    </div>

    <script>
        let currentScanId = null;
        let pollInterval = null;
        let scanData = [];

        document.getElementById('portRange').addEventListener('change', function() {
            document.getElementById('customPortRow').style.display = 
                this.value === 'custom' ? 'flex' : 'none';
        });

        function startScan() {
            const target = document.getElementById('targetInput').value. trim();
            if (!target) {
                alert('Please enter a target host');
                return;
            }

            const portRange = document.getElementById('portRange').value;
            let ports = portRange;
            if (portRange === 'custom') {
                const start = document.getElementById('startPort').value;
                const end = document.getElementById('endPort').value;
                ports = `${start}-${end}`;
            }

            const config = {
                target: target,
                ports: ports,
                scan_tcp: document.getElementById('scanTCP').checked,
                scan_udp: document.getElementById('scanUDP').checked,
                detect_service: document.getElementById('detectService').checked,
                detect_os: document.getElementById('detectOS').checked,
                check_alive:  document.getElementById('checkAlive').checked,
                traceroute:  document.getElementById('traceroute').checked
            };

            document.getElementById('scanBtn').disabled = true;
            document.getElementById('progressSection').classList.add('active');
            document.getElementById('resultsSection').classList.remove('active');
            document.getElementById('emptyState').style.display = 'none';
            document.getElementById('progressFill').style.width = '10%';

            fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                    resetUI();
                    return;
                }
                currentScanId = data.scan_id;
                pollResults();
            })
            .catch(error => {
                alert('Error: ' + error);
                resetUI();
            });
        }

        function pollResults() {
            let progress = 20;
            pollInterval = setInterval(() => {
                fetch(`/api/results/${currentScanId}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            clearInterval(pollInterval);
                            alert('Error: ' + data.error);
                            resetUI();
                            return;
                        }

                        document.getElementById('progressText').textContent = data.step || 'Processing...';
                        progress = Math.min(progress + 5, 95);
                        document.getElementById('progressFill').style.width = progress + '%';

                        if (data.status === 'completed') {
                            clearInterval(pollInterval);
                            document. getElementById('progressFill').style.width = '100%';
                            setTimeout(() => displayResults(data), 500);
                        } else if (data.status === 'error') {
                            clearInterval(pollInterval);
                            alert('Scan error: ' + data.error);
                            resetUI();
                        }
                    })
                    .catch(error => {
                        clearInterval(pollInterval);
                        alert('Error: ' + error);
                        resetUI();
                    });
            }, 2000);
        }

        function displayResults(data) {
            document.getElementById('progressSection').classList.remove('active');
            document.getElementById('resultsSection').classList.add('active');
            document.getElementById('scanBtn').disabled = false;

            // Header info
            document.getElementById('hostIP').textContent = data.ip_address || '-';
            document. getElementById('hostname').textContent = data.hostname || '-';
            
            if (data.os_guess && data.os_guess !== 'Unknown') {
                document.getElementById('osInfo').innerHTML = 
                    `<div class="os-badge">🖥️ ${data.os_guess}</div>`;
            }

            // Stats
            const openCount = data.ports ?  data.ports.filter(p => p. state === 'open').length : 0;
            const filteredCount = data.ports ? data. ports.filter(p => p. state === 'filtered').length : 0;
            
            document.getElementById('openPorts').textContent = openCount;
            document.getElementById('filteredPorts').textContent = filteredCount;
            document.getElementById('scanDuration').textContent = data.scan_duration || '-';

            // Scan parameters
            document.getElementById('paramHost').textContent = data.target;
            document.getElementById('paramProtocol').textContent = data. protocols || 'TCP/UDP';
            document.getElementById('paramScanType').textContent = data.scan_type || 'Deep Scan';
            document.getElementById('paramPorts').textContent = data.port_range || '-';
            document.getElementById('paramAlive').textContent = data. check_alive ?  'True' : 'False';
            document.getElementById('paramService').textContent = data.detect_service ?  'True' : 'False';
            document.getElementById('paramOS').textContent = data.detect_os ? 'True' :  'False';
            document. getElementById('paramTrace').textContent = data.traceroute ? 'True' : 'False';

            // Ports table
            scanData = data.ports || [];
            renderTable(scanData);
        }

        function renderTable(ports) {
            const tbody = document.getElementById('portsTableBody');
            tbody.innerHTML = '';

            if (ports.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 2rem;">No open or filtered ports detected</td></tr>';
                return;
            }

            ports. forEach(port => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><span class="port-badge">${port.port}</span></td>
                    <td><span class="protocol-badge protocol-${port.protocol. toLowerCase()}">${port.protocol.toUpperCase()}</span></td>
                    <td><span class="state-${port.state.toLowerCase()}">${port.state}</span></td>
                    <td>${port.service || '-'}</td>
                    <td>${port.product || '-'}</td>
                    <td>${port.version || '-'}</td>
                    <td>${port.details || '-'}</td>
                `;
                tbody.appendChild(row);
            });
        }

        function sortTable() {
            const sortBy = document.getElementById('sortBy').value;
            const order = document.getElementById('sortOrder').value;

            const sorted = [...scanData]. sort((a, b) => {
                let aVal = a[sortBy];
                let bVal = b[sortBy];

                if (sortBy === 'port') {
                    aVal = parseInt(aVal);
                    bVal = parseInt(bVal);
                }

                if (order === 'asc') {
                    return aVal > bVal ? 1 :  -1;
                } else {
                    return aVal < bVal ? 1 : -1;
                }
            });

            renderTable(sorted);
        }

        function resetUI() {
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('progressSection').classList.remove('active');
            if (! document.getElementById('resultsSection').classList.contains('active')) {
                document.getElementById('emptyState').style.display = 'block';
            }
        }
    </script>
</body>
</html>
"""

# Scanner implementation
class DeepScanner:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.ip_address = None
        self. hostname = None
        self.os_guess = "Unknown"
        self.ports = []
        self.alive = False
        self.latency = None
        self.start_time = None
        
        # Common ports
        self.top_100_tcp = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                            1723, 3306, 3389, 5900, 8080, 8443, 20, 69, 137, 138, 161, 162, 389,
                            636, 1433, 1434, 1521, 2049, 2121, 3268, 5432, 5800, 5901, 6379, 8000,
                            8008, 8081, 8888, 9000, 9090, 9100, 9200, 9300, 10000, 27017, 50000,
                            515, 548, 631, 873, 902, 1080, 1194, 1352, 1433, 1720, 2082, 2083,
                            2222, 3000, 3128, 3690, 4443, 4444, 4567, 5000, 5001, 5060, 5222,
                            5269, 5357, 5432, 5555, 5672, 5985, 5986, 6000, 6001, 6379, 6666,
                            7001, 7070, 7777, 8001, 8009, 8042, 8069, 8082, 8083, 8181, 8200,
                            8300, 8500, 8600, 8834, 9001, 9080, 9081, 9418, 9999, 11211, 27018]
        
        self.top_100_udp = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520,
                            631, 1434, 1900, 4500, 49152, 49153, 49154, 5353, 1701, 1812, 1813,
                            2049, 3478, 5060, 5353, 10000, 17185, 20031, 33434, 47808, 49156,
                            111, 177, 427, 497, 512, 513, 518, 626, 996, 997, 998, 1023, 1025,
                            1026, 1027, 1028, 1029, 1030, 1645, 1646, 1718, 1719, 2000, 2223,
                            3283, 3456, 4000, 5000, 5001, 5004, 5005, 5351, 6346, 9200, 10080,
                            11487, 16464, 16465, 16470, 16471, 17185, 19283, 19682, 20031, 26000,
                            26262, 30120, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
                            32775, 33281, 41524, 44818, 49152, 49153, 49154, 54321, 57621, 58002]

    def resolve_target(self):
        """Resolve hostname to IP"""
        try:
            ipaddress.ip_address(self.target)
            self.ip_address = self.target
            try:
                self.hostname = socket.gethostbyaddr(self.target)[0]
            except: 
                self.hostname = self. target
        except ValueError:
            try:
                self.ip_address = socket.gethostbyname(self.target)
                self.hostname = self.target
            except socket.gaierror:
                raise Exception(f"Could not resolve:  {self.target}")

    def check_alive(self):
        """Ping host to check if alive"""
        if not self.config.get('check_alive', True):
            self.alive = True
            return
        
        try:
            param = '-n' if os.name == 'nt' else '-c'
            start = time.time()
            result = subprocess.run(
                ['ping', param, '2', self.ip_address],
                capture_output=True,
                text=True,
                timeout=5
            )
            self.latency = round((time.time() - start) * 1000, 2)
            self.alive = result.returncode == 0
        except: 
            self.alive = False

    def scan_tcp_port(self, port):
        """Scan single TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.ip_address, port))
            sock.close()
            
            if result == 0:
                return {'port': port, 'protocol': 'tcp', 'state': 'open'}
        except:
            pass
        return None

    def scan_udp_port(self, port):
        """Scan single UDP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # Send empty packet
            sock.sendto(b'', (self.ip_address, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return {'port': port, 'protocol': 'udp', 'state': 'open'}
            except socket.timeout:
                # Timeout usually means open|filtered for UDP
                sock.close()
                return {'port': port, 'protocol':  'udp', 'state': 'open|filtered'}
        except:
            pass
        return None

    def get_service_name(self, port, protocol):
        """Get service name for port"""
        try:
            return socket.getservbyport(port, protocol)
        except:
            # Custom common services
            services = {
                80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 23: 'telnet',
                25: 'smtp', 53: 'dns', 110: 'pop3', 143: 'imap', 3306: 'mysql',
                5432: 'postgresql', 6379: 'redis', 27017: 'mongodb', 3389: 'rdp',
                5900: 'vnc', 8080: 'http-proxy', 8443: 'https-alt', 445: 'smb',
                139: 'netbios', 389: 'ldap', 636: 'ldaps', 1433: 'mssql', 
                8000: 'http-alt', 9200: 'elasticsearch', 5672: 'amqp', 1521: 'oracle'
            }
            return services. get(port, 'unknown')

    def detect_service(self, port, protocol):
        """Detect service and version"""
        if protocol != 'tcp': 
            return None, None, None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip_address, port))
            
            # Try to grab banner
            if port in [80, 8080, 8000, 8443]: 
                request = f"GET / HTTP/1.1\r\nHost: {self.ip_address}\r\n\r\n"
                sock.send(request.encode())
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse banner for product/version
            product, version = self.parse_banner(banner, port)
            return banner[: 100], product, version
            
        except:
            return None, None, None

    def parse_banner(self, banner, port):
        """Parse banner for product and version"""
        product = None
        version = None
        
        banner_lower = banner.lower()
        
        # HTTP servers
        if 'server: ' in banner_lower:
            match = re.search(r'server:\s*([^\r\n]+)', banner_lower)
            if match: 
                server_info = match.group(1).strip()
                parts = server_info.split('/')
                product = parts[0]. strip()
                if len(parts) > 1:
                    version = parts[1].split()[0].strip()
        
        # SSH
        elif 'ssh' in banner_lower:
            match = re.search(r'ssh-([\d\.]+)', banner_lower)
            product = 'OpenSSH' if 'openssh' in banner_lower else 'SSH'
            if match:
                version = match. group(1)
        
        # FTP
        elif port == 21 or 'ftp' in banner_lower:
            if 'proftpd' in banner_lower:
                product = 'ProFTPD'
                match = re.search(r'proftpd\s+([\d\.a-z]+)', banner_lower)
                if match:
                    version = match.group(1)
            elif 'vsftpd' in banner_lower:
                product = 'vsftpd'
                match = re.search(r'vsftpd\s+([\d\.]+)', banner_lower)
                if match:
                    version = match.group(1)
        
        # MySQL
        elif 'mysql' in banner_lower or port == 3306:
            product = 'MySQL'
            match = re.search(r'([\d\.]+)', banner)
            if match:
                version = match.group(1)
        
        return product or '-', version or '-'

    def detect_os(self):
        """Detect operating system"""
        try:
            param = '-n' if os.name == 'nt' else '-c'
            result = subprocess.run(
                ['ping', param, '1', self. ip_address],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            ttl_match = re.search(r'ttl[=\s]+(\d+)', result.stdout.lower())
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if 0 < ttl <= 64:
                    self.os_guess = 'Linux'
                elif 64 < ttl <= 128:
                    self.os_guess = 'Windows'
                elif 128 < ttl <= 255:
                    self.os_guess = 'Cisco/Network Device'
            
            # Refine based on open ports
            tcp_ports = [p['port'] for p in self.ports if p['protocol'] == 'tcp']
            if 3389 in tcp_ports or 445 in tcp_ports:
                self.os_guess = 'Windows'
            elif 22 in tcp_ports and 80 in tcp_ports:
                self. os_guess = 'Linux'
        except:
            pass

    def get_ports_to_scan(self):
        """Get list of ports to scan"""
        port_range = self.config.get('ports', 'top100')
        
        if port_range == 'top100': 
            return self.top_100_tcp, self.top_100_udp[: 50]
        elif port_range == 'top1000':
            return list(range(1, 1001)), self.top_100_udp
        elif port_range == 'all':
            return list(range(1, 65536)), self.top_100_udp
        elif '-' in str(port_range):
            start, end = map(int, port_range.split('-'))
            tcp_ports = list(range(start, end + 1))
            udp_ports = [p for p in self.top_100_udp if start <= p <= end]
            return tcp_ports, udp_ports
        else:
            return self.top_100_tcp, self.top_100_udp[: 50]

    def scan_ports(self):
        """Scan all ports"""
        tcp_ports, udp_ports = self.get_ports_to_scan()
        
        results = []
        
        # TCP Scan
        if self.config.get('scan_tcp', True):
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(self.scan_tcp_port, port): port for port in tcp_ports}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results. append(result)
        
        # UDP Scan
        if self.config.get('scan_udp', True):
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.scan_udp_port, port): port for port in udp_ports}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results. append(result)
        
        self.ports = results

    def enrich_ports(self):
        """Add service detection to ports"""
        if not self.config.get('detect_service', True):
            for port_info in self.ports:
                port_info['service'] = self.get_service_name(port_info['port'], port_info['protocol'])
                port_info['product'] = '-'
                port_info['version'] = '-'
                port_info['details'] = '-'
            return
        
        for port_info in self.ports:
            service_name = self.get_service_name(port_info['port'], port_info['protocol'])
            port_info['service'] = service_name
            
            if port_info['state'] == 'open' and port_info['protocol'] == 'tcp':
                banner, product, version = self.detect_service(port_info['port'], port_info['protocol'])
                port_info['product'] = product or '-'
                port_info['version'] = version or '-'
                port_info['details'] = banner[: 50] if banner else '-'
            else:
                port_info['product'] = '-'
                port_info['version'] = '-'
                port_info['details'] = '-'

    def run_scan(self):
        """Execute full scan"""
        self.start_time = time.time()
        results = {
            'status': 'running',
            'target': self.target,
            'step': 'Starting scan.. .'
        }
        
        try:
            # Step 1: Resolve
            results['step'] = 'Resolving target...'
            self.resolve_target()
            results['ip_address'] = self.ip_address
            results['hostname'] = self.hostname
            
            # Step 2: Check alive
            results['step'] = 'Checking if host is alive...'
            self. check_alive()
            results['alive'] = self.alive
            
            # Step 3: Scan ports
            results['step'] = 'Scanning ports (this may take several minutes)...'
            self.scan_ports()
            
            # Step 4: Service detection
            results['step'] = 'Detecting services...'
            self.enrich_ports()
            
            # Step 5: OS detection
            if self.config.get('detect_os', True):
                results['step'] = 'Detecting operating system...'
                self.detect_os()
            
            # Final results
            duration = round(time.time() - self.start_time, 2)
            results['status'] = 'completed'
            results['step'] = 'Scan complete!'
            results['ports'] = sorted(self.ports, key=lambda x: x['port'])
            results['os_guess'] = self.os_guess
            results['scan_duration'] = f"{duration}s"
            results['scan_type'] = 'Deep Scan'
            results['protocols'] = []
            if self.config.get('scan_tcp'): results['protocols'].append('TCP')
            if self.config. get('scan_udp'): results['protocols'].append('UDP')
            results['protocols'] = '/'.join(results['protocols'])
            results['port_range'] = self.config. get('ports', 'top100')
            results['check_alive'] = self.config.get('check_alive', True)
            results['detect_service'] = self.config. get('detect_service', True)
            results['detect_os'] = self.config.get('detect_os', True)
            results['traceroute'] = self.config. get('traceroute', False)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results

# Flask routes
scan_results = {}

@app.route('/')
def index():
    return HTML_TEMPLATE

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    
    if not target: 
        return jsonify({'error': 'Target required'}), 400
    
    scan_id = f"{target}_{int(time.time())}"
    
    def run_scan_thread():
        scanner = DeepScanner(target, data)
        results = scanner.run_scan()
        scan_results[scan_id] = results
    
    thread = threading.Thread(target=run_scan_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    results = scan_results.get(scan_id)
    if not results:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(results)

if __name__ == '__main__': 
    print("=" * 70)
    print("🔍 DEEP NETWORK SCANNER")
    print("=" * 70)
    print("Server running on:  http://localhost:5000")
    print("Features:")
    print("  ✓ TCP & UDP port scanning")
    print("  ✓ Service detection and banner grabbing")
    print("  ✓ OS fingerprinting")
    print("  ✓ All 65,535 ports supported")
    print("  ✓ Professional tabular results display")
    print("=" * 70)
    print("\nOpen http://localhost:5000 in your browser\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
