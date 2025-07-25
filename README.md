# Network Packet Sniffer

A real-time network packet sniffer web application built with Flask backend and Next.js frontend.

## Features

- Real-time packet capture using Scapy
- WebSocket communication for live updates
- Modern hacker-style UI with neon accents
- Pause/Resume packet capture
- Packet filtering and throttling
- Responsive design with Tailwind CSS

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
\`\`\`bash
cd backend
\`\`\`

2. Install Python dependencies:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

3. Run the Flask server with sudo privileges (required for packet capture):
\`\`\`bash
sudo python app.py
\`\`\`

The backend will start on `http://localhost:5000`

### Frontend Setup

1. Install Node.js dependencies:
\`\`\`bash
npm install
# or
pnpm install
\`\`\`

2. Start the development server:
\`\`\`bash
npm run dev
# or
pnpm dev
\`\`\`

The frontend will be available at `http://localhost:3000`

## Usage

1. Start the backend server with sudo privileges
2. Start the frontend development server
3. Open your browser to `http://localhost:3000`
4. The app will automatically start capturing packets
5. Use the Pause/Resume button to control packet capture
6. Use the Clear button to clear the packet list

## Requirements

- Python 3.8+
- Node.js 16+
- Sudo privileges for packet capture
- Network interface for packet sniffing

## Security Note

This tool captures network packets and requires elevated privileges. Use responsibly and only on networks you own or have permission to monitor.
# network-trafficking-tool
