"use client"

import { useState, useEffect, useRef } from "react"
import { io, type Socket } from "socket.io-client"

interface PacketData {
  id: number
  timestamp: string
  protocol: string
  size: number
  src_ip: string
  dst_ip: string
  src_port: string | number
  dst_port: string | number
  src_mac: string
  dst_mac: string
}

interface ConnectionStatus {
  status: string
  capturing: boolean
}

export default function PacketSniffer() {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [packets, setPackets] = useState<PacketData[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [isCapturing, setIsCapturing] = useState(false)
  const [packetCount, setPacketCount] = useState(0)
  const packetsEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Initialize socket connection
    const newSocket = io("http://localhost:5000", {
      transports: ["websocket", "polling"],
    })

    newSocket.on("connect", () => {
      console.log("Connected to server")
      setIsConnected(true)
    })

    newSocket.on("disconnect", () => {
      console.log("Disconnected from server")
      setIsConnected(false)
      setIsCapturing(false)
    })

    newSocket.on("connection_status", (data: ConnectionStatus) => {
      setIsCapturing(data.capturing)
    })

    newSocket.on("capture_status", (data: { capturing: boolean }) => {
      setIsCapturing(data.capturing)
    })

    newSocket.on("new_packet", (packetData: PacketData) => {
      setPackets((prev) => {
        const newPackets = [...prev, packetData]
        // Keep only last 1000 packets to prevent memory issues
        if (newPackets.length > 1000) {
          return newPackets.slice(-1000)
        }
        return newPackets
      })
      setPacketCount((prev) => prev + 1)
    })

    setSocket(newSocket)

    return () => {
      newSocket.close()
    }
  }, [])

  useEffect(() => {
    // Auto-scroll to bottom when new packets arrive
    if (packetsEndRef.current) {
      packetsEndRef.current.scrollIntoView({ behavior: "smooth" })
    }
  }, [packets])

  const handlePauseResume = () => {
    if (!socket) return

    if (isCapturing) {
      socket.emit("pause_capture")
    } else {
      socket.emit("resume_capture")
    }
  }

  const clearPackets = () => {
    setPackets([])
    setPacketCount(0)
  }

  const getProtocolColor = (protocol: string) => {
    switch (protocol.toUpperCase()) {
      case "TCP":
        return "text-cyber-accent"
      case "UDP":
        return "text-cyber-green"
      case "ICMP":
        return "text-cyber-blue"
      case "ARP":
        return "text-cyber-purple"
      default:
        return "text-gray-400"
    }
  }

  return (
    <div className="min-h-screen bg-cyber-dark p-4">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-cyber-accent mb-2 animate-glow">Network Packet Sniffer</h1>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center space-x-6">
            <div className="flex items-center">
              <span className={`status-indicator ${isConnected ? "status-connected" : "status-disconnected"}`} />
              <span className="text-sm">{isConnected ? "Connected" : "Disconnected"}</span>
            </div>
            <div className="flex items-center">
              <span className={`status-indicator ${isCapturing ? "status-connected" : "status-paused"}`} />
              <span className="text-sm">{isCapturing ? "Capturing" : "Paused"}</span>
            </div>
            <div className="text-sm text-cyber-accent">Packets: {packetCount}</div>
          </div>

          <div className="flex space-x-3">
            <button
              onClick={handlePauseResume}
              disabled={!isConnected}
              className={`px-4 py-2 rounded font-medium transition-all duration-200 ${
                isConnected
                  ? isCapturing
                    ? "bg-yellow-600 hover:bg-yellow-700 text-white"
                    : "bg-cyber-accent hover:bg-cyan-400 text-black"
                  : "bg-gray-600 text-gray-400 cursor-not-allowed"
              }`}
            >
              {isCapturing ? "Pause" : "Resume"}
            </button>

            <button
              onClick={clearPackets}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium transition-all duration-200"
            >
              Clear
            </button>
          </div>
        </div>
      </div>

      {/* Packet Table */}
      <div className="cyber-border rounded-lg overflow-hidden">
        <div className="bg-cyber-gray p-3">
          <h2 className="text-lg font-semibold text-cyber-accent">Live Packet Feed</h2>
        </div>

        <div className="bg-cyber-darker">
          {/* Table Header */}
          <div className="grid grid-cols-12 gap-2 p-3 bg-cyber-gray text-sm font-semibold border-b border-cyber-accent">
            <div className="col-span-1">ID</div>
            <div className="col-span-1">Time</div>
            <div className="col-span-1">Protocol</div>
            <div className="col-span-2">Source IP</div>
            <div className="col-span-2">Dest IP</div>
            <div className="col-span-1">Src Port</div>
            <div className="col-span-1">Dst Port</div>
            <div className="col-span-2">Source MAC</div>
            <div className="col-span-1">Size</div>
          </div>

          {/* Packet List */}
          <div className="h-96 overflow-y-auto">
            {packets.length === 0 ? (
              <div className="p-8 text-center text-gray-400">
                {isConnected ? (
                  isCapturing ? (
                    <div className="flex items-center justify-center">
                      <div className="animate-pulse-slow mr-2">●</div>
                      Waiting for packets...
                    </div>
                  ) : (
                    "Packet capture is paused. Click Resume to start capturing."
                  )
                ) : (
                  "Connecting to packet sniffer server..."
                )}
              </div>
            ) : (
              packets.map((packet) => (
                <div
                  key={packet.id}
                  className="grid grid-cols-12 gap-2 p-2 text-xs border-b border-gray-700 packet-row transition-all duration-150"
                >
                  <div className="col-span-1 text-cyber-accent font-mono">{packet.id}</div>
                  <div className="col-span-1 text-gray-300 font-mono">{packet.timestamp}</div>
                  <div className={`col-span-1 font-semibold ${getProtocolColor(packet.protocol)}`}>
                    {packet.protocol}
                  </div>
                  <div className="col-span-2 font-mono text-cyan-300">{packet.src_ip}</div>
                  <div className="col-span-2 font-mono text-cyan-300">{packet.dst_ip}</div>
                  <div className="col-span-1 text-gray-300">{packet.src_port}</div>
                  <div className="col-span-1 text-gray-300">{packet.dst_port}</div>
                  <div className="col-span-2 font-mono text-gray-400 text-xs truncate">{packet.src_mac}</div>
                  <div className="col-span-1 text-gray-300">{packet.size}B</div>
                </div>
              ))
            )}
            <div ref={packetsEndRef} />
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-6 text-center text-sm text-gray-400">
        <p>Real-time network packet analysis • Run backend with sudo privileges</p>
        <p className="mt-1">Backend: Flask + Scapy • Frontend: Next.js + Socket.IO</p>
      </div>
    </div>
  )
}
