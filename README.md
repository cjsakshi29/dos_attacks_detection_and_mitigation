# Real-Time Behavior-Based DDoS Detection with Web Dashboard

A security system designed for real-time monitoring, detection, and mitigation of DDoS attacks using behavioral analysis and dynamic trust scoring.

## Features
- **Live Web Dashboard**: Dark-themed UI with auto-refreshing logs and IP status summary.
- **Three-Tier Trust States**:
  - `NORMAL` (70-100): Full access.
  - `SUSPICIOUS` (30-70): Flagged, but still allowed.
  - `BLOCKED` (0-30): Access Denied (HTTP 403).
- **Multi-Device Support**: Deploy across LAN, monitor traffic from any device.
- **Adaptive Recovery**: Trust scores recover over time if traffic stabilizes.

## 📡 Deployment Instructions (LAN)

### 1. Identify Server IP
Find the local IP of the device running the server:
- **Mac/Linux**: Open terminal and run `ifconfig` (look for `inet` under `en0` or `wlan0`).
- **Windows**: Open cmd and run `ipconfig` (look for `IPv4 Address`).
- *Example: 192.168.1.15*

### 2. Run the Server
```bash
# From project root
python3 server/server.py
```
- **Dashboard**: Visit `http://<YOUR_IP>:5001` in your browser.
- **API (Traffic)**: Traffic is received at `http://<YOUR_IP>:5001/api`.

### 3. Run the Client (Simulation)
On another device (or same), run the simulator:

**Normal Mode (Trusted):**
```bash
python3 client/client.py --mode normal --url http://192.168.1.15:5001
```

**Attack Mode (Trigger Block):**
```bash
python3 client/client.py --mode attack --url http://192.168.1.15:5001
```

## How It Works
1. **Detection**: Tracks request frequency within a 5-second window.
2. **Analysis**: If requests > 10, the score decays by 10 points per violation.
3. **Mitigation**: Once the score hits 30 or below, the IP is automatically blocked.
4. **Recovery**: If an IP stops attacking, its score increases by 2 points every normal request.
