from flask import Flask, request, jsonify, render_template, abort, after_this_request, redirect, url_for
from detector import TrustManager
import os
import time
import threading
import csv
from datetime import datetime

app = Flask(__name__)

# Initialize Dual-Engine TrustManager
detector = TrustManager(window_size=5, base_penalty=20)

activity_logs = []
MAX_LOGS = 50
LOG_FILE = os.path.join(os.path.dirname(__file__), 'security_logs.csv')
csv_lock = threading.Lock()

# Initialize CSV file with headers if it doesn't exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "IP", "Score", "RPS", "RPM", "KB_s", "Ratio", "Status", "AI_Conf", "Reason"])

def write_to_csv(entry):
    with csv_lock:
        with open(LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                entry['timestamp'], entry['ip'], entry['score'], 
                entry['rps'], entry['rpm'], entry['kb_s'], 
                entry['ratio'], entry['status'], entry['confidence'], entry['reason']
            ])

def background_recovery():
    """Thread function to run auto-recovery periodically."""
    while True:
        time.sleep(10) # Run every 10 seconds
        events = detector.recover_scores()
        for event in events:
            log_entry = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "ip": event['ip'],
                "score": f"{event['new_score']:.1f}",
                "rps": "0.0", "rpm": 0, "kb_s": "0.00", "ratio": "0.0",
                "status": detector.get_status(event['new_score'])[0],
                "confidence": "N/A",
                "reason": f"Self-Healing (from {event['old_score']:.0f})"
            }
            activity_logs.append(log_entry)
            if len(activity_logs) > MAX_LOGS:
                activity_logs.pop(0)
            write_to_csv(log_entry)

# Start recovery thread
threading.Thread(target=background_recovery, daemon=True).start()

@app.route('/')
def dashboard():
    ip_summary = []
    # Collect summary data
    for ip, score in detector.trust_scores.items():
        status, _ = detector.get_status(score)
        ip_summary.append({
            "ip": ip,
            "score": f"{score:.1f}",
            "status": status,
            "requests": detector.response_stats.get(ip, {"total":0})["total"]
        })
    
    return render_template('dashboard.html', 
                          logs=reversed(activity_logs), 
                          ip_summary=ip_summary,
                          stats={
                              "total_attacks": detector.total_attacks_detected,
                              "blocked_count": len(detector.currently_blocked_ips)
                          },
                          last_updated=datetime.now().strftime("%H:%M:%S"))

@app.route('/unblock/<ip>')
def unblock_ip(ip):
    if detector.unblock(ip):
        # Log the manual unblock
        log_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "ip": ip,
            "score": "71.0",
            "rps": "0.0", "rpm": 0, "kb_s": "0.00", "ratio": "0.0",
            "status": "NORMAL",
            "confidence": "N/A",
            "reason": "Admin Manual Unblock"
        }
        activity_logs.append(log_entry)
        write_to_csv(log_entry)
        return redirect(url_for('dashboard'))
    return "IP not found", 404

@app.route('/api')
def handle_api():
    client_ip = request.remote_addr
    byte_size = request.content_length if request.content_length else len(request.data) + 500
    
    score, status, metrics, is_blocked = detector.log_request(client_ip, byte_size)
    
    if not is_blocked:
        @after_this_request
        def mark_success(response):
            if response.status_code == 200:
                detector.log_success(client_ip)
            return response

    log_entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "ip": client_ip,
        "score": f"{score:.1f}",
        "rps": f"{metrics['rps']:.1f}",
        "rpm": metrics['rpm'],
        "kb_s": f"{metrics['kb_s']:.2f}",
        "ratio": f"{metrics['ratio']:.1f}",
        "status": status,
        "confidence": f"{metrics['confidence']*100:.0f}%",
        "reason": metrics['reason']
    }
    
    activity_logs.append(log_entry)
    if len(activity_logs) > MAX_LOGS:
        activity_logs.pop(0)
        
    # Write to CSV
    write_to_csv(log_entry)

    if is_blocked:
        return jsonify({
            "error": "Forbidden",
            "message": "Security Mitigation: Pattern or Volume violation.",
            "metrics": metrics,
            "trust_score": f"{score:.1f}",
            "status": "BLOCKED"
        }), 403

    return jsonify({
        "message": "Request allowed",
        "trust_score": score,
        "metrics": metrics,
        "status": status
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    print(f"🚀 Resilience-Enabled DDoS Protection Server starting on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
