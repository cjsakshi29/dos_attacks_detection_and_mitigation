import requests
import time
import argparse
import sys

def send_requests(url, count, delay, mode):
    # Ensure URL ends with /api
    if not url.endswith('/api'):
        url = url.rstrip('/') + '/api'
        
    print(f"\n--- DDoS Traffic Simulator ---")
    print(f"Target: {url}")
    print(f"Profile: {mode.upper()} mode")
    print(f"Requests: {count} | Delay: {delay}s")
    print("-" * 40)

    success_count = 0
    blocked_count = 0

    for i in range(1, count + 1):
        try:
            start_time = time.time()
            # The server now listens at /api for traffic
            if mode == "payload_attack":
                # Send malicious Layer 7 payload
                response = requests.post(url, data="<script>alert('XSS')</script>", timeout=5)
            else:
                response = requests.get(url, timeout=5)
            
            latency = (time.time() - start_time) * 1000
            
            status_code = response.status_code
            data = response.json()
            
            score = data.get('trust_score', 'N/A')
            status = data.get('status', 'N/A')
            
            if status_code == 200:
                success_count += 1
                msg = f"OK | Score: {score} | status: {status}"
            elif status_code == 403:
                blocked_count += 1
                msg = f"BLOCKED 🚫 | Score: {score}"
            else:
                msg = f"Status {status_code}"

            print(f"[{i:03}] {msg} ({latency:3.0f}ms)")
            
            if status_code == 403:
                print("\n🛑 IP has been blocked by the server. Simulation halted.")
                break

        except requests.exceptions.RequestException as e:
            print(f"[{i:03}] ❌ Connection Error: {e}")
            break

        if delay > 0:
            time.sleep(delay)

    print("-" * 40)
    print(f"Results: Success={success_count}, Blocked={blocked_count}")
    print("-" * 40)

def main():
    parser = argparse.ArgumentParser(description="DDoS Simulation Client")
    # Defaulting to 5001 as previously identified the port conflict
    parser.add_argument("--url", default="http://127.0.0.1:5001", help="Server URL (e.g., http://192.168.1.5:5001)")
    parser.add_argument("--mode", choices=["normal", "attack", "payload_attack"], default="normal", help="Traffic mode")
    args = parser.parse_args()

    if args.mode == "normal":
        # Slow requests: 15 req, 2s delay (Window limit is 10 req / 5s)
        send_requests(args.url, count=20, delay=2.0, mode="normal")
    elif args.mode == "attack":
        # Rapid requests: 50 req, 0.1s delay
        send_requests(args.url, count=50, delay=0.1, mode="attack")
    elif args.mode == "payload_attack":
        # Slow requests (will bypass volume limit), but sends malicious signature
        print("\n[!] Sending Malicious Payload Signature (Layer 7 Attack)")
        send_requests(args.url, count=3, delay=2.0, mode="payload_attack")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user.")
        sys.exit(0)
