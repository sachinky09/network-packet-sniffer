from flask import Flask
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
from packet_sniffer import PacketSniffer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet-sniffer-secret'
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Global state
packet_sniffer = None
is_capturing = False
connected_clients = 0

@socketio.on('connect')
def handle_connect():
    global connected_clients, packet_sniffer, is_capturing
    connected_clients += 1
    print(f'Client connected. Total clients: {connected_clients}')
    
    # Start packet capture if this is the first client
    if connected_clients == 1 and not is_capturing:
        start_packet_capture()
    
    emit('connection_status', {'status': 'connected', 'capturing': is_capturing})

@socketio.on('disconnect')
def handle_disconnect():
    global connected_clients, is_capturing
    connected_clients -= 1
    print(f'Client disconnected. Total clients: {connected_clients}')
    
    # Stop packet capture if no clients are connected
    if connected_clients == 0 and is_capturing:
        stop_packet_capture()

@socketio.on('pause_capture')
def handle_pause():
    global is_capturing
    is_capturing = False
    if packet_sniffer:
        packet_sniffer.pause()
    socketio.emit('capture_status', {'capturing': False})
    print('Packet capture paused')

@socketio.on('resume_capture')
def handle_resume():
    global is_capturing
    is_capturing = True
    if packet_sniffer:
        packet_sniffer.resume()
    socketio.emit('capture_status', {'capturing': True})
    print('Packet capture resumed')

def start_packet_capture():
    global packet_sniffer, is_capturing
    if not packet_sniffer:
        packet_sniffer = PacketSniffer(packet_callback)
    
    is_capturing = True
    capture_thread = threading.Thread(target=packet_sniffer.start_capture)
    capture_thread.daemon = True
    capture_thread.start()
    print('Packet capture started')

def stop_packet_capture():
    global packet_sniffer, is_capturing
    is_capturing = False
    if packet_sniffer:
        packet_sniffer.stop()
    print('Packet capture stopped')

def packet_callback(packet_data):
    """Callback function to handle captured packets"""
    if is_capturing and connected_clients > 0:
        socketio.emit('new_packet', packet_data)

if __name__ == '__main__':
    print('Starting Packet Sniffer Server...')
    print('Make sure to run with sudo privileges for packet capture')
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
