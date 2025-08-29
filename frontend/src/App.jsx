import React from "react";
import PacketList from "./PacketList";

export default function App() {
  return (
    <div style={{ padding: "16px" }}>
      <h1>Network Packet Sniffer</h1>
      <PacketList />
    </div>
  );
}
