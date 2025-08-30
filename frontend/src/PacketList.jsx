// frontend/src/PacketList.jsx
import React, { useEffect, useRef, useState } from "react";
import "./styles.css";
import dotenv from "dotenv";
dotenv.config();


const API = process.env.API;

function timeFromIso(iso) {
  try { return new Date(iso).toLocaleTimeString(); }
  catch { return iso; }
}

export default function PacketList() {
  const [interfaces, setInterfaces] = useState([]);
  const [iface, setIface] = useState("");
  const [running, setRunning] = useState(false);
  const [packets, setPackets] = useState([]);
  const [follow, setFollow] = useState(true);
  const pollRef = useRef(null);
  const tableWrapRef = useRef(null);

  useEffect(() => {
    fetch(`${API}/interfaces`).then(r => r.json()).then(list => {
      if (Array.isArray(list)) {
        setInterfaces(list);
        if (!iface && list.length) setIface(list[0]);
      }
    }).catch(()=>{});
  }, []);

  // Poll packets when running
  useEffect(() => {
    if (running) {
      // immediate fetch
      fetchPackets();
      pollRef.current = setInterval(fetchPackets, 1000);
    } else {
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => pollRef.current && clearInterval(pollRef.current);
  }, [running, iface]);

  function fetchPackets() {
    fetch(`${API}/packets`).then(r => r.json()).then(list => {
      if (Array.isArray(list)) {
        setPackets(list.slice()); // copy
        if (follow && tableWrapRef.current) {
          // scroll to bottom
          const el = tableWrapRef.current;
          el.scrollTop = el.scrollHeight;
        }
      }
    }).catch(()=>{});
  }

  async function start() {
    if (!iface) return;
    await fetch(`${API}/start`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({interface: iface})
    });
    setRunning(true);
  }

  async function stop() {
    await fetch(`${API}/stop`, {method:"POST"});
    setRunning(false);
  }

  async function clearPackets() {
    await fetch(`${API}/clear`, {method:"POST"});
    setPackets([]);
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="title">Network Packet Sniffer</div>
        <div className="controls">
          <select value={iface} onChange={e=>setIface(e.target.value)} disabled={running}>
            {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
          </select>
          <button onClick={start} disabled={running || !iface}>Start</button>
          <button onClick={stop} disabled={!running}>Stop</button>
          <button onClick={clearPackets}>Clear</button>
          <label className="follow">
            <input type="checkbox" checked={follow} onChange={e=>setFollow(e.target.checked)} />
            Follow
          </label>
        </div>
      </header>

      <div className="table-wrap" ref={tableWrapRef}>
        <table className="pkt-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Src</th>
              <th>Src Vendor</th>
              <th>Dst</th>
              <th>Dst Vendor</th>
              <th>Proto</th>
              <th>Size (B)</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((p, idx) => (
              <tr key={idx} className={p.meant_for_me ? "to-me" : "not-me"}>
                <td>{timeFromIso(p.time_iso)}</td>
                <td>{p.src_ip}{p.src_port ? `:${p.src_port}` : ""}</td>
                <td>{p.src_vendor}</td>
                <td>{p.dst_ip}{p.dst_port ? `:${p.dst_port}` : ""}</td>
                <td>{p.dst_vendor}</td>
                <td>{p.protocol}</td>
                <td>{p.size_bytes}</td>
                <td className="summary">{p.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
