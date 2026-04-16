from flask import Flask, request, jsonify, render_template, abort, after_this_request, redirect, url_for, send_file
from detector import TrustManager
import os
import time
import threading
import csv
from datetime import datetime
import psutil
import pandas as pd
import matplotlib
matplotlib.use('Agg') # Headless mode for server graphics
import matplotlib.pyplot as plt
import io

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

def process_detection(client_ip, byte_size, payload=""):
    """Unified logic for detection, trust scoring, and logging."""
    score, status, metrics, is_blocked = detector.log_request(client_ip, byte_size, payload)
    
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
        
    write_to_csv(log_entry)
    return score, status, metrics, is_blocked

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

@app.route('/app')
def protected_app():
    """The user-facing protected News Feed application with DPI and Hardware-Adaptive logic."""
    client_ip = request.remote_addr
    byte_size = 1200 # Estimated page size in bytes
    payload = str(request.args.to_dict()) if request.args else ""
    
    score, status, metrics, is_blocked = process_detection(client_ip, byte_size, payload)
    
    if is_blocked:
        return render_template('error_403.html', 
                             ip=client_ip, 
                             score=f"{score:.1f}", 
                             reason=metrics['reason']), 403

    detector.log_success(client_ip)
    return render_template('app.html')

@app.route('/unblock/<ip>')
def unblock_ip(ip):
    if detector.unblock(ip):
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

@app.route('/status_api')
def status_api():
    ip_summary = []
    normal, suspicious, blocked = 0, 0, 0
    total_trust = 0
    
    for ip, score in detector.trust_scores.items():
        status, _ = detector.get_status(score)
        total_trust += score
        if status == 'NORMAL': normal += 1
        elif status == 'SUSPICIOUS': suspicious += 1
        else: blocked += 1
        
        ip_summary.append({
            "ip": ip, "score": f"{score:.1f}", "status": status,
            "requests": detector.response_stats.get(ip, {"total":0})["total"]
        })
        
    avg_trust = (total_trust / len(detector.trust_scores)) if detector.trust_scores else 100
    
    return jsonify({
        "logs": list(reversed(activity_logs))[:15],
        "ip_summary": ip_summary,
        "graphs": {
            "time": datetime.now().strftime("%H:%M:%S"),
            "cpu": psutil.cpu_percent(),
            "ram": psutil.virtual_memory().percent,
            "avg_trust": avg_trust,
            "rps": sum(len(hist) for hist in detector.rps_history.values()),
            "normal_ips": normal,
            "suspicious_ips": suspicious,
            "blocked_ips": blocked
        },
        "stats": {
            "total_attacks": detector.total_attacks_detected,
            "blocked_count": len(detector.currently_blocked_ips),
            "hw_threshold": detector.rps_threshold
        }
    })

@app.route('/generate_report', methods=['POST'])
def generate_report():
    try:
        start_datetime = request.form.get('start_time')
        end_datetime = request.form.get('end_time')
        if not os.path.exists(LOG_FILE): return "No log data available.", 404
            
        df = pd.read_csv(LOG_FILE)
        df['dt'] = pd.to_datetime('today').normalize() + pd.to_timedelta(df['Timestamp'])
        
        if start_datetime and end_datetime:
            s_dt = pd.to_datetime(start_datetime)
            e_dt = pd.to_datetime(end_datetime)
            df = df[(df['dt'] >= s_dt) & (df['dt'] <= e_dt)]
            
        if len(df) == 0: return "No data for selected timeframe.", 404
            
        plt.style.use('dark_background')
        fig, axs = plt.subplots(3, 1, figsize=(10, 15))
        fig.suptitle(f'Security Performance/Analytics Report', fontsize=16)

        axs[0].plot(df['Timestamp'], df['RPS'], label='RPS', color='#3b82f6')
        axs[0].set_title('Network Volume (RPS)')
        axs[0].set_ylabel('Requests / Sec')
        axs[0].tick_params(axis='x', rotation=45)
        axs[0].xaxis.set_major_locator(plt.MaxNLocator(5))
        
        axs[1].scatter(df['Timestamp'], df['Score'], color='#10b981', alpha=0.5)
        axs[1].set_title('Trust Score Fluctuations')
        axs[1].set_ylabel('Trust (0-100)')
        axs[1].xaxis.set_major_locator(plt.MaxNLocator(5))
        
        status_counts = df['Status'].value_counts()
        colors = {'NORMAL': '#10b981', 'SUSPICIOUS': '#f59e0b', 'BLOCKED': '#ef4444'}
        plot_colors = [colors.get(x, '#888') for x in status_counts.index]
        axs[2].pie(status_counts, labels=status_counts.index, colors=plot_colors, autopct='%1.1f%%')
        axs[2].set_title('Traffic Classification Distribution')

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        pdf_buffer = io.BytesIO()
        plt.savefig(pdf_buffer, format='pdf')
        pdf_buffer.seek(0)
        plt.close(fig)
        
        filename = f"SOC_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(pdf_buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')
    except Exception as e:
        return f"Failed to generate report: {str(e)}", 500

@app.route('/api', methods=['GET', 'POST'])
def handle_api():
    client_ip = request.remote_addr
    byte_size = request.content_length if request.content_length else len(request.data) + 500
    payload = request.get_data(as_text=True)
    
    score, status, metrics, is_blocked = process_detection(client_ip, byte_size, payload)
    
    if not is_blocked:
        @after_this_request
        def mark_success(response):
            if response.status_code == 200: detector.log_success(client_ip)
            return response

    if is_blocked:
        return jsonify({
            "error": "Forbidden",
            "message": "Security Mitigation: Pattern or Volume violation.",
            "metrics": metrics,
            "trust_score": f"{score:.1f}",
            "status": "BLOCKED"
        }), 403

    return jsonify({"message": "Request allowed", "trust_score": score, "metrics": metrics, "status": status})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    print(f"[Server] Integrated Multi-Novelty Server starting on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
