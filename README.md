# Network Packet Sniffer

A lightweight **Network Packet Sniffer** with a simple backend (Flask + Scapy) and a React frontend.  
Capture live packets, inspect IP/MAC/vendor/protocol/size and control capture from the browser.

---

## Features

- Live packet capture (select interface)
- Start / Stop / Clear capture controls
- Shows: timestamp, source/destination IP & port, source/destination MAC, vendor (MAC→vendor), protocol name, packet size (bytes), brief summary
- Highlights packets meant for the local host (clear visual distinction)
- Bounded in-memory history (configurable)
- Professional, minimal UI for demos/interviews

---

## Quick Setup

### Backend (Python)

1. Create & activate a virtual environment (recommended)
   - Linux/macOS:
     ```
     python3 -m venv backend/.venv
     source backend/.venv/bin/activate
     ```
   - Windows (PowerShell):
     ```
     python -m venv backend\.venv
     backend\.venv\Scripts\Activate.ps1
     ```

2. Install dependencies

pip install -r backend/requirements.txt


3. Run backend (root required for sniffing)

From project root

sudo python3 backend/app.py

The backend listens on `http://0.0.0.0:5000` by default.

---

### Frontend (React)

1. In the `frontend` directory, install packages:

cd frontend
npm install


2. Start the dev server:

npm start


3. Open your browser at the address provided by the dev server (usually `http://localhost:3000`).

---

## Project structure

network-packet-sniffer/
- backend/
- app.py               # Flask backend (sniffer + API)
- requirements.txt     # Python deps (Flask, scapy, flask-cors, mac-vendor-lookup)
- frontend/
- src/
 - PacketList.jsx     # Main UI component
 - styles.css         # Styles used by the component
- package.json
- README.md

---

## Backend: requirements.txt (example)

Place this in `backend/requirements.txt`:

flask
flask-cors
scapy
mac-vendor-lookup


Install with:

pip install -r backend/requirements.txt


---

## Security & Permissions

- Packet sniffing requires elevated privileges. On Linux run the backend with `sudo` or grant specific capabilities to the Python binary (advanced).
- Do **not** commit virtual environments (`.venv`) or `node_modules` to version control. Add them to `.gitignore`.

---

## Notes and tips

- If you see a lot of `127.0.0.1` entries, that is loopback (local processes talking to each other). Loopback packets have no meaningful MAC vendor; the UI labels them `Localhost`.
- On switched Ethernet networks, you will only see traffic that the NIC receives (your host, broadcast, multicast) unless you use monitor/promiscuous setups or special capture hardware.
- On Wi-Fi, use monitor mode to capture more frames (but encryption and single-channel limits apply).
- The included frontend polls `/packets` periodically; it's simple and reliable. If you want lower-latency updates, the backend can be extended to use WebSockets.

---

## Troubleshooting

- `ModuleNotFoundError: No module named 'flask'` → activate your venv and run `pip install -r backend/requirements.txt`.
- `PermissionError` when sniffing → run the backend as root (`sudo`) or give capabilities to python (advanced).
- If you accidentally committed `.venv`:
  - `git rm -r --cached backend/.venv`
  - add `.venv/` to `.gitignore`
  - `git commit -m "remove .venv from repo"`

---

## License

MIT License — feel free to use and adapt.

---

If you want, I can now:
- Generate a `README.md` including screenshots (if you provide them), or
- Produce a cleaned `.gitignore` suitable for this project, or
- Give a short walkthrough of the three primary files (`backend/app.py`, `frontend/src/PacketList.jsx`, `frontend/src/styles.css`) line-by-line.

