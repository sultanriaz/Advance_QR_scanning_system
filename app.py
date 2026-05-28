"""
Secure QR Analyzer - Main Application
COMPLETELY DYNAMIC - No hardcoded values
"""

import atexit
import logging
import sqlite3
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import os
import json

import cv2
import validators
from flask import Flask, render_template, Response, jsonify, request
from flask_cors import CORS

from heuristics import analyze_url
from reputation import get_reputation_adjustment, reload_lists

# -----------------------------
# Application Configuration
# -----------------------------
app = Flask(__name__)
CORS(app)

class Config:
    DB_PATH = "scans.db"
    CAMERA_ID = 0
    MIN_SCAN_INTERVAL = 1.0
    MAX_HISTORY_LIMIT = 50
    CAMERA_RECONNECT_DELAY = 2.0
    
    ALLOWED_SCHEMES = ['http', 'https']
    BLOCKED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', '::1']

# -----------------------------
# Logging Setup
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------
# Database Manager - FIXED
# -----------------------------
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
        logger.info(f"Database initialized at {db_path}")
    
    def _init_db(self):
        """Initialize database with proper schema"""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    domain TEXT,
                    score INTEGER,
                    risk TEXT,
                    confidence INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            
            # Check if table has data
            cursor = conn.execute("SELECT COUNT(*) FROM scans")
            count = cursor.fetchone()[0]
            logger.info(f"Database has {count} existing scans")
            
        except Exception as e:
            logger.error(f"Database init error: {e}")
        finally:
            conn.close()
    
    def insert_scan(self, url: str, domain: str, score: int, risk: str, confidence: int):
        """Insert a scan record"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO scans (url, domain, score, risk, confidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (url, domain, score, risk, confidence, datetime.now()))
            conn.commit()
            conn.close()
            logger.info(f"Inserted scan: {domain} - {risk} (Score: {score})")
            return True
        except Exception as e:
            logger.error(f"Insert error: {e}")
            return False
    
    def get_latest_scan(self) -> Dict:
        """Get the most recent scan"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT url, domain, score, risk, confidence, timestamp
                FROM scans 
                ORDER BY timestamp DESC 
                LIMIT 1
            """)
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "url": row["url"],
                    "domain": row["domain"],
                    "risk_score": row["score"],
                    "risk_level": row["risk"],
                    "confidence": row["confidence"],
                    "timestamp": row["timestamp"],
                    "reasons": []  # Reasons not stored in DB, will be empty
                }
            return {
                "url": "",
                "domain": "",
                "risk_score": 0,
                "risk_level": "",
                "confidence": 0,
                "timestamp": None,
                "reasons": []
            }
        except Exception as e:
            logger.error(f"Get latest error: {e}")
            return {}
    
    def get_history(self, limit: int = 50) -> list:
        """Get scan history"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT url, domain, score, risk, confidence, timestamp
                FROM scans 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            conn.close()
            
            return [
                {
                    "url": row["url"],
                    "domain": row["domain"],
                    "score": row["score"],
                    "risk": row["risk"],
                    "confidence": row["confidence"],
                    "timestamp": row["timestamp"]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"History error: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get real-time statistics from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Total scans
            cursor = conn.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]
            
            # Threats detected (DANGEROUS + CRITICAL + SUSPICIOUS)
            cursor = conn.execute("""
                SELECT 
                    SUM(CASE WHEN risk IN ('DANGEROUS', 'CRITICAL') THEN 1 ELSE 0 END) as dangerous,
                    SUM(CASE WHEN risk = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN risk = 'SAFE' THEN 1 ELSE 0 END) as safe,
                    AVG(score) as avg_score
                FROM scans
            """)
            row = cursor.fetchone()
            conn.close()
            
            dangerous = row[0] or 0
            suspicious = row[1] or 0
            safe = row[2] or 0
            avg_score = round(row[3] or 0, 2)
            
            stats = {
                "total_scans": total_scans,
                "dangerous": dangerous,
                "suspicious": suspicious,
                "safe": safe,
                "average_risk_score": avg_score,
                "threats_detected": dangerous + suspicious,
                "threat_rate": round(((dangerous + suspicious) / total_scans * 100) if total_scans > 0 else 0, 1)
            }
            
            logger.debug(f"Stats: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return {
                "total_scans": 0,
                "dangerous": 0,
                "suspicious": 0,
                "safe": 0,
                "average_risk_score": 0,
                "threats_detected": 0,
                "threat_rate": 0
            }

# Initialize database
db_manager = DatabaseManager(Config.DB_PATH)

# -----------------------------
# Camera Management
# -----------------------------
class CameraManager:
    def __init__(self, camera_id: int = 0):
        self.camera_id = camera_id
        self.cap = None
        self.lock = threading.Lock()
        
    def get_camera(self):
        with self.lock:
            if self.cap is None or not self.cap.isOpened():
                self.cap = cv2.VideoCapture(self.camera_id)
                if self.cap.isOpened():
                    self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                    self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                    logger.info("Camera opened")
            return self.cap
    
    def release(self):
        if self.cap:
            self.cap.release()
            logger.info("Camera released")

camera_manager = CameraManager(Config.CAMERA_ID)

# -----------------------------
# QR Code Scanner
# -----------------------------
class QRScanner:
    def __init__(self):
        self.last_scan_time = 0
        self.last_url = ""
    
    def process_frame(self, frame):
        current_time = time.time()
        detector = cv2.QRCodeDetector()
        
        try:
            data, bbox, _ = detector.detectAndDecode(frame)
            if bbox is not None and data:
                if (current_time - self.last_scan_time) >= Config.MIN_SCAN_INTERVAL:
                    self.last_scan_time = current_time
                    self.last_url = data
                    return data, bbox
            return None, None
        except Exception as e:
            logger.error(f"QR error: {e}")
            return None, None

qr_scanner = QRScanner()

# -----------------------------
# URL Analysis Engine
# -----------------------------
class URLAnalysisEngine:
    @staticmethod
    def analyze(url: str) -> Dict:
        """Analyze URL and return results"""
        
        # Basic URL validation
        if not url or not validators.url(url):
            return {
                "url": url,
                "domain": "invalid",
                "risk_score": 0,
                "risk_level": "INVALID",
                "confidence": 0,
                "reasons": ["Invalid URL format"]
            }
        
        # Extract domain
        try:
            from tldextract import extract
            extracted = extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        except:
            domain = urlparse(url).netloc
        
        # Run heuristics
        try:
            analysis = analyze_url(url)
            score = analysis.get("score", 0)
            reasons = analysis.get("reasons", [])
        except Exception as e:
            logger.error(f"Heuristics error: {e}")
            score = 50
            reasons = ["Analysis fallback"]
        
        # Apply reputation
        try:
            rep_adjust, rep_reasons = get_reputation_adjustment(domain)
            score += rep_adjust
            reasons.extend(rep_reasons)
        except Exception as e:
            logger.error(f"Reputation error: {e}")
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Determine risk level
        if score < 25:
            risk_level = "SAFE"
        elif score < 55:
            risk_level = "SUSPICIOUS"
        elif score < 80:
            risk_level = "DANGEROUS"
        else:
            risk_level = "CRITICAL"
        
        # Calculate confidence
        confidence = URLAnalysisEngine._calculate_confidence(score)
        
        return {
            "url": url,
            "domain": domain,
            "risk_score": score,
            "risk_level": risk_level,
            "confidence": confidence,
            "reasons": reasons
        }
    
    @staticmethod
    def _calculate_confidence(score: int) -> int:
        if score < 25:
            return 95
        elif score < 55:
            return 75
        elif score < 80:
            return 65
        else:
            return 85

analysis_engine = URLAnalysisEngine()

# -----------------------------
# Video Feed Generation
# -----------------------------
def generate_frames():
    import numpy as np
    
    while True:
        camera = camera_manager.get_camera()
        if camera is None:
            frame = np.zeros((480, 640, 3), dtype=np.uint8)
            cv2.putText(frame, "Camera Not Available", (150, 240), 
                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
        else:
            ret, frame = camera.read()
            if not ret:
                frame = np.zeros((480, 640, 3), dtype=np.uint8)
                cv2.putText(frame, "Camera Error", (200, 240), 
                           cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
            else:
                # Process QR code
                data, bbox = qr_scanner.process_frame(frame)
                
                if bbox is not None and data:
                    # Draw bounding box
                    pts = bbox[0].astype(int)
                    for i in range(len(pts)):
                        cv2.line(frame, tuple(pts[i]), tuple(pts[(i+1)%len(pts)]), (0,255,0), 2)
                    
                    # Analyze URL if valid
                    if validators.url(data):
                        result = analysis_engine.analyze(data)
                        
                        # Save to database
                        db_manager.insert_scan(
                            url=result["url"],
                            domain=result["domain"],
                            score=result["risk_score"],
                            risk=result["risk_level"],
                            confidence=result["confidence"]
                        )
                        
                        # Display result
                        text = f"{result['risk_level']} ({result['risk_score']})"
                        color = (0,255,0) if result['risk_level'] == 'SAFE' else \
                               (0,165,255) if result['risk_level'] == 'SUSPICIOUS' else \
                               (0,0,255)
                        cv2.putText(frame, text, (20, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
                    else:
                        cv2.putText(frame, "Invalid URL", (20, 40), 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,0,255), 2)
        
        # Encode and yield frame
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
        yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
        time.sleep(0.03)

# -----------------------------
# Flask Routes
# -----------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    camera_status = camera_manager.get_camera() is not None
    return jsonify({
        "status": "healthy" if camera_status else "degraded",
        "camera": camera_status,
        "database": os.path.exists(Config.DB_PATH),
        "timestamp": datetime.now().isoformat()
    })

@app.route('/latest_scan')
def latest_scan_route():
    """Returns the most recent scan from database"""
    scan = db_manager.get_latest_scan()
    return jsonify(scan)

@app.route('/history')
def history_route():
    """Returns scan history"""
    limit = request.args.get('limit', 20, type=int)
    history = db_manager.get_history(limit)
    return jsonify(history)

@app.route('/api/stats')
def stats_route():
    """Returns REAL statistics from database"""
    stats = db_manager.get_statistics()
    return jsonify(stats)

@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    """Clear all scan history (for testing)"""
    try:
        conn = sqlite3.connect(Config.DB_PATH)
        conn.execute("DELETE FROM scans")
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "History cleared"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# -----------------------------
# Cleanup
# -----------------------------
def cleanup():
    camera_manager.release()
    logger.info("Shutdown complete")

atexit.register(cleanup)

# -----------------------------
# Main Entry Point
# -----------------------------
if __name__ == "__main__":
    print("\n" + "="*60)
    print(" SECURE QR ANALYZER - DYNAMIC VERSION")
    print("="*60)
    print(f" Database: {Config.DB_PATH}")
    print(f" Camera: ID {Config.CAMERA_ID}")
    print(f" Starting server at http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    
    
    
