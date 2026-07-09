"""Real-time dashboard using FastAPI and WebSockets."""

import asyncio
import logging
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

logger = logging.getLogger(__name__)

app = FastAPI(title="FOCP Sec Real-time Dashboard")

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.latest_scan_result: dict[str, Any] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # Send latest result immediately upon connection if available
        if self.latest_scan_result:
            await websocket.send_json(self.latest_scan_result)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_result(self, result: dict[str, Any]):
        self.latest_scan_result = result
        for connection in self.active_connections:
            try:
                await connection.send_json(result)
            except Exception as e:
                logger.error("Failed to send websocket message: %s", e)

manager = ConnectionManager()

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>FOCP Sec Real-time Scanner</title>
        <style>
            body { font-family: -apple-system, sans-serif; margin: 20px; background: #f5f7fa; color: #333; }
            h1 { color: #2c3e50; }
            #status { padding: 10px; border-radius: 5px; margin-bottom: 20px; font-weight: bold; }
            .connected { background: #d4edda; color: #155724; }
            .disconnected { background: #f8d7da; color: #721c24; }
            .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .finding { border-left: 4px solid #333; padding-left: 10px; margin-bottom: 15px; }
            .critical { border-left-color: #e74c3c; }
            .high { border-left-color: #e67e22; }
            .medium { border-left-color: #f1c40f; }
            .low { border-left-color: #3498db; }
            .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; color: white; }
            .badge.critical { background: #e74c3c; }
            .badge.high { background: #e67e22; }
            .badge.medium { background: #f1c40f; }
            .badge.low { background: #3498db; }
        </style>
    </head>
    <body>
        <h1>FOCP Sec Real-time Scanner</h1>
        <div id="status" class="disconnected">Connecting...</div>
        
        <div class="card">
            <h2>Project Status</h2>
            <div id="project-info">Awaiting scan data...</div>
        </div>
        
        <div class="card">
            <h2>Findings (<span id="findings-count">0</span>)</h2>
            <div id="findings-list"></div>
        </div>
        
        <script>
            var ws = new WebSocket("ws://localhost:8080/ws");
            var statusDiv = document.getElementById('status');
            
            ws.onopen = function() {
                statusDiv.textContent = "Connected to Scanner";
                statusDiv.className = "connected";
            };
            
            ws.onclose = function() {
                statusDiv.textContent = "Disconnected from Scanner";
                statusDiv.className = "disconnected";
            };
            
            ws.onmessage = function(event) {
                var data = JSON.parse(event.data);
                
                // Update project info
                var infoHtml = `
                    <p><strong>Score:</strong> ${data.score.overall}/100</p>
                    <p><strong>Files Scanned:</strong> ${data.project.file_count}</p>
                    <p><strong>Last Scan:</strong> ${new Date(data.timestamp).toLocaleTimeString()}</p>
                `;
                document.getElementById('project-info').innerHTML = infoHtml;
                
                // Update findings
                var allFindings = data.findings.concat(data.dependency_findings || []);
                document.getElementById('findings-count').textContent = allFindings.length;
                
                var findingsHtml = "";
                allFindings.forEach(f => {
                    var sev = f.severity.toLowerCase();
                    var location = f.file_path ? ` - ${f.file_path}:${f.line_number || ''}` : '';
                    findingsHtml += `
                        <div class="finding ${sev}">
                            <h4><span class="badge ${sev}">${f.severity.toUpperCase()}</span> ${f.title}</h4>
                            <p>${f.description}</p>
                            <code>${location}</code>
                        </div>
                    `;
                });
                document.getElementById('findings-list').innerHTML = findingsHtml;
            };
        </script>
    </body>
</html>
"""

@app.get("/")
async def get():
    return HTMLResponse(html)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

def run_dashboard(host: str = "127.0.0.1", port: int = 8080):
    """Run the FastAPI dashboard server."""
    logger.info("Starting real-time dashboard on http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="warning")
