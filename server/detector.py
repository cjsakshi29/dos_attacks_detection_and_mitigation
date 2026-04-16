import psutil
import time
from collections import deque
import numpy as np
import joblib
import os

class TrustManager:
    def __init__(self, window_size=5, base_penalty=20):
        self.window_size = window_size      # AI/Frequency window
        self.base_penalty = base_penalty    # AI penalty weight
        
        # Thresholds
        self.default_rps_threshold = 10.0
        self.rps_threshold = self.default_rps_threshold
        self.rpm_threshold = 100.0
        self.byte_rate_limit = 500.0        # KB/s
        self.recovery_threshold = 25.0      # Seconds of inactivity before recovery
        
        # Deep Packet Inspection Signatures (Novelty)
        self.malicious_signatures = [
            "<script>", "javascript:", "onerror=", "onload=",  # XSS
            "UNION SELECT", "OR 1=1", "--", "DROP TABLE",      # SQLi
            "../../", "/etc/passwd", "cmd.exe"                 # LFI / RCE
        ]
        
        # Load the ML Model
        model_path = os.path.join(os.path.dirname(__file__), 'ddos_model.pkl')
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            print("[Detector] Machine Learning model loaded.")
        else:
            self.model = None

        # Per-IP Data
        self.request_history = {}    # Timestamps (5s window)
        self.rps_history = {}        # Timestamps (1s window)
        self.rpm_history = {}        # Timestamps (60s window)
        self.byte_history = {}       # List of (timestamp, size)
        self.response_stats = {}     # {total_req, success_resp}
        self.trust_scores = {}
        self.last_seen = {}          # Track last request time for recovery
        
        # Global Statistics
        self.total_attacks_detected = 0
        self.currently_blocked_ips = set()

    def get_score(self, ip):
        return self.trust_scores.get(ip, 100.0)

    def extract_features(self, history):
        if len(history) < 2: return None
        intervals = np.diff(list(history))
        return {
            'count': len(history),
            'mean_interval': np.mean(intervals),
            'std_interval': np.std(intervals),
            'max_interval': np.max(intervals)
        }

    def _cleanup_history(self, history, window, now):
        while history and history[0] < now - window:
            history.popleft()

    def log_request(self, ip, byte_size=0, payload=""):
        """Logs a request and computes dual-engine metrics including DPI."""
        now = time.time()
        self.last_seen[ip] = now
        
        # Initialize IP storage
        if ip not in self.request_history:
            self.request_history[ip] = deque()
            self.rps_history[ip] = deque()
            self.rpm_history[ip] = deque()
            self.byte_history[ip] = deque()
            self.response_stats[ip] = {"total": 0, "success": 0}
            self.trust_scores[ip] = 100.0
            
        # Update histories
        self.request_history[ip].append(now)
        self.rps_history[ip].append(now)
        self.rpm_history[ip].append(now)
        self.byte_history[ip].append((now, byte_size))
        self.response_stats[ip]["total"] += 1
        
        # Cleanup
        self._cleanup_history(self.request_history[ip], self.window_size, now)
        self._cleanup_history(self.rps_history[ip], 1.0, now)
        self._cleanup_history(self.rpm_history[ip], 60.0, now)
        # Cleanup byte history
        while self.byte_history[ip] and self.byte_history[ip][0][0] < now - 1.0:
            self.byte_history[ip].popleft()
            
        # 0. Adaptive Hardware Defense (Novelty)
        cpu_load = psutil.cpu_percent(interval=None)
        if cpu_load > 60.0:
            # CPU is struggling, panic mode (stricter thresholds)
            self.rps_threshold = max(3.0, self.rps_threshold - 1.0)
        else:
            # CPU is fine, relax thresholds back to normal
            self.rps_threshold = min(self.default_rps_threshold, self.rps_threshold + 0.5)
            
        # 1. Calculate Volume Metrics
        rps = len(self.rps_history[ip])
        rpm = len(self.rpm_history[ip])
        total_kb = sum(b[1] for b in self.byte_history[ip]) / 1024.0
        byte_rate = total_kb # KB/s (since window is 1s)
        
        success = self.response_stats[ip]["success"]
        total = self.response_stats[ip]["total"]
        ratio = total / max(1, success)
        
        # 2. AI Behavioral Analysis
        frequency = len(self.request_history[ip])
        current_score = self.trust_scores[ip]
        confidence = 0.0
        reasons = []

        if self.model and frequency >= 2:
            features = self.extract_features(self.request_history[ip])
            if features:
                import pandas as pd
                X = pd.DataFrame([{
                    'count': features['count'],
                    'mean_interval': features['mean_interval'],
                    'std_interval': features['std_interval'],
                    'max_interval': features['max_interval']
                }])
                confidence = self.model.predict_proba(X)[0][1]
        
        # 3. Decision Logic (Dual Engine & DPI)
        penalty = 0.0
        
        # Deep Packet Inspection (Layer 7 Novelty)
        if payload:
            payload_upper = payload.upper()
            for sig in self.malicious_signatures:
                if sig.upper() in payload_upper:
                    penalty += 100  # Instant critical penalty
                    reasons.append(f"Signature Match: {sig}")
                    break  # Stop checking signatures if one matches
        
        # AI Penalty
        if confidence > 0.5:
            penalty += self.base_penalty * confidence
            reasons.append(f"AI:Robotic({confidence*100:.0f}%)")
            
        # Volume Penalties
        if rps > self.rps_threshold:
            penalty += (rps - self.rps_threshold) * 5
            reasons.append(f"High-RPS({rps:.1f})")
            
        if byte_rate > self.byte_rate_limit:
            penalty += 15
            reasons.append(f"Heavy-Flow({byte_rate:.1f}KB/s)")
            
        if ratio > 5.0 and total > 10:
            penalty += 10
            reasons.append(f"Error-Ratio({ratio:.1f})")

        if penalty > 0:
            self.total_attacks_detected += 1
            current_score = max(0, current_score - penalty)
        else:
            # Subtle recovery during normal requests
            if current_score < 100:
                current_score = min(100.0, current_score + 2.0)
                
        self.trust_scores[ip] = current_score
        label, is_blocked = self.get_status(current_score)
        
        # Track blocked status
        if is_blocked:
            self.currently_blocked_ips.add(ip)
        else:
            self.currently_blocked_ips.discard(ip)
        
        metrics = {
            "rps": rps,
            "rpm": rpm,
            "kb_s": byte_rate,
            "ratio": ratio,
            "confidence": confidence,
            "reason": ", ".join(reasons) if reasons else "Normal",
            "cpu": cpu_load,
            "hw_threshold": self.rps_threshold
        }
        
        return current_score, label, metrics, is_blocked

    def log_success(self, ip):
        """Called when a request is successfully processed (HTTP 200)."""
        if ip in self.response_stats:
            self.response_stats[ip]["success"] += 1

    def get_status(self, score):
        if score >= 70: return "NORMAL", False
        elif score > 30: return "SUSPICIOUS", False
        else: return "BLOCKED", True

    def unblock(self, ip):
        """Manual administrative unblock."""
        if ip in self.trust_scores:
            self.trust_scores[ip] = 71.0 # Reset to bottom of NORMAL
            self.currently_blocked_ips.discard(ip)
            # Clear all histories to give a clean start
            self.request_history[ip] = deque()
            self.rps_history[ip] = deque()
            self.rpm_history[ip] = deque()
            self.byte_history[ip] = deque()
            self.last_seen[ip] = time.time()
            return True
        return False

    def recover_scores(self):
        """Background job: Gradually recover trust for inactive IPs."""
        now = time.time()
        recovery_events = []
        
        for ip, last_time in list(self.last_seen.items()):
            score = self.trust_scores.get(ip, 100.0)
            if score < 100.0 and (now - last_time) > self.recovery_threshold:
                # Gradual recovery: +5 points per check
                new_score = min(100.0, score + 5.0)
                self.trust_scores[ip] = new_score
                
                # Check status change
                label, is_blocked = self.get_status(new_score)
                if not is_blocked:
                    self.currently_blocked_ips.discard(ip)
                
                # If recovered to NORMAL, clear histories to prevent stale RPM spikes
                if label == "NORMAL":
                    self.request_history[ip] = deque()
                    self.rps_history[ip] = deque()
                    self.rpm_history[ip] = deque()
                    self.byte_history[ip] = deque()

                recovery_events.append({
                    "ip": ip,
                    "old_score": score,
                    "new_score": new_score
                })
        return recovery_events
