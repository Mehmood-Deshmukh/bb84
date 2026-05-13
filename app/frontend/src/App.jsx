import React, { useState, useEffect } from 'react'

function App() {
  const [status, setStatus] = useState('CONNECTING...')
  const [peers, setPeers] = useState([])
  const [socket, setSocket] = useState(null)

  useEffect(() => {
    // 1. Establish WebSocket connection
    let ws;
    let reconnectTimeout;

    const connectWebSocket = () => {
      ws = new WebSocket('ws://127.0.0.1:8000/api/ws/status')
      
      ws.onopen = () => {
        setStatus('CONNECTED TO BACKEND')
      }
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (data.type === 'info') {
          setStatus(`CONNECTED: ${data.message}`)
        }
      }
      
      ws.onclose = () => {
        setStatus('DISCONNECTED. RETRYING...')
        // Try to reconnect in 2 seconds
        reconnectTimeout = setTimeout(connectWebSocket, 2000)
      }

      setSocket(ws)
    }

    connectWebSocket()

    // 2. Poll for discovered peers
    const fetchPeers = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/peers')
        const data = await response.json()
        setPeers(data.peers || [])
      } catch (err) {
        console.error("Failed to fetch peers", err)
      }
    }

    fetchPeers()
    const interval = setInterval(fetchPeers, 2000)

    return () => {
      if (ws) ws.close()
      clearTimeout(reconnectTimeout)
      clearInterval(interval)
    }
  }, [])

  return (
    <div className="flex flex-col items-center justify-center min-h-screen w-full p-6 font-sans">
      <div className="w-full max-w-3xl mb-12">
        <h1 className="text-6xl font-black text-gruvbox-orange-bright tracking-tighter uppercase mb-4">
          QKD NODE
        </h1>
        <div className="flex items-center gap-3 border-2 border-gruvbox-bg-soft bg-gruvbox-bg p-3">
          <div className={`w-4 h-4 ${status.startsWith('CONNECTED') ? 'bg-gruvbox-green-bright' : 'bg-gruvbox-red-bright'}`}></div>
          <p className="text-lg text-gruvbox-fg-bright font-mono font-bold tracking-tight">
            STATUS: {status}
          </p>
        </div>
      </div>

      <div className="w-full max-w-3xl bg-gruvbox-bg border-4 border-gruvbox-fg-bright p-8" style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-fg-bright)' }}>
        <div className="flex justify-between items-end mb-8 border-b-4 border-gruvbox-bg-soft pb-4">
          <h2 className="text-3xl font-black text-gruvbox-fg-bright uppercase tracking-tighter">
            Discovered Peers
          </h2>
          <span className="bg-gruvbox-blue-bright text-gruvbox-bg-hard font-mono font-bold px-3 py-1 text-sm">
            TOTAL: {peers.length}
          </span>
        </div>
        
        {peers.length === 0 ? (
          <div className="text-center py-16 bg-gruvbox-bg-soft border-2 border-gruvbox-bg-hard">
            <p className="text-gruvbox-fg font-mono font-bold text-lg tracking-widest uppercase animate-pulse">
              [ SEARCHING LOCAL NETWORK ]
            </p>
          </div>
        ) : (
          <div className="grid gap-6">
            {peers.map((peer, i) => (
              <div key={i} className="flex flex-col sm:flex-row sm:items-center justify-between bg-gruvbox-bg-hard border-2 border-gruvbox-bg-soft p-5 hover:border-gruvbox-orange-bright transition-colors">
                <div className="mb-4 sm:mb-0">
                  <h3 className="font-black text-gruvbox-fg-bright text-2xl uppercase tracking-tighter">{peer.name}</h3>
                  <p className="text-gruvbox-yellow-bright font-mono font-bold text-sm mt-1">
                    IP: {peer.ip} | PORT: {peer.port}
                  </p>
                </div>
                <button className="bg-gruvbox-green-bright hover:bg-gruvbox-fg-bright text-gruvbox-bg-hard font-black font-mono py-3 px-6 transition-colors uppercase tracking-widest">
                  Connect
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default App
