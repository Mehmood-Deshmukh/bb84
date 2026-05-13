import React, { useState, useEffect, useRef } from 'react'

function App() {
  const [status, setStatus] = useState('CONNECTING...')
  const [peers, setPeers] = useState([])
  const [socket, setSocket] = useState(null)
  const [selectedFile, setSelectedFile] = useState(null)
  const [toast, setToast] = useState(null)
  const [logs, setLogs] = useState([])
  const [incomingRequest, setIncomingRequest] = useState(null)
  const [username, setUsername] = useState(localStorage.getItem("qkd_username") || "")
  const [isUsernameSet, setIsUsernameSet] = useState(!!localStorage.getItem("qkd_username"))
  const [transferProgress, setTransferProgress] = useState(null)
  const isTransferringRef = useRef(false)

  const showToast = (message, type = 'info') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4000)
  }

  const handleConnect = async (peer) => {
    if (!selectedFile) {
      showToast("[ ERROR ] PLEASE SELECT A FILE TO TRANSMIT FIRST.", 'error')
      return
    }

    const formData = new FormData()
    formData.append("file", selectedFile)
    formData.append("target_ip", peer.ip)
    formData.append("target_port", peer.port)

    setLogs([])

    try {
      const response = await fetch('http://127.0.0.1:8000/api/transfer', {
        method: 'POST',
        body: formData,
      })
      const data = await response.json()
      if (data.status === 'ok') {
        showToast("[ SUCCESS ] " + data.message, 'success')
      } else {
        showToast("[ ERROR ] " + data.detail, 'error')
      }
    } catch (err) {
      showToast("[ ERROR ] INITIATING TRANSFER: " + err.message, 'error')
    }
  }

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
        } else if (data.type === 'transfer_log') {
          setLogs(prev => [...prev, data.message])
          const progressMatch = data.message.match(/chunk \d+\/\d+ \(([\d.]+)%\)/)
          if (progressMatch) {
             setTransferProgress(parseFloat(progressMatch[1]))
          } else if (data.message.includes("Transfer Process Complete") || data.message.includes("Receiver Process Complete")) {
             setTransferProgress(100)
             isTransferringRef.current = false
             setTimeout(() => setTransferProgress(null), 3000)
          } else if (data.message.includes("Starting transfer") || data.message.includes("Receiver launched") || data.message.includes("Starting Receiver")) {
             setTransferProgress(0)
             isTransferringRef.current = true
          }
        } else if (data.type === 'incoming_request') {
          if (isTransferringRef.current) {
             fetch('http://127.0.0.1:8000/api/respond-transfer', {
               method: 'POST',
               headers: { 'Content-Type': 'application/json' },
               body: JSON.stringify({ transfer_id: data.transfer_id, accept: false })
             }).catch(e => console.error(e))
             return;
          }
          setIncomingRequest(data)
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

    // Send username on reload
    const storedUser = localStorage.getItem("qkd_username")
    if (storedUser) {
      fetch('http://127.0.0.1:8000/api/set-username', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ username: storedUser })
      }).catch(err => console.error(err))
    }

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
    <div className="flex flex-col items-center justify-center min-h-screen w-full p-6 font-sans relative">
      {!isUsernameSet && (
        <div className="fixed inset-0 bg-black/90 z-[200] flex items-center justify-center p-4">
          <div className="bg-gruvbox-bg border-4 border-gruvbox-yellow-bright p-8 max-w-md w-full" style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-yellow-bright)' }}>
            <h2 className="text-3xl font-black text-gruvbox-yellow-bright uppercase tracking-tighter mb-4">Identify Node</h2>
            <p className="text-gruvbox-fg mb-4 font-mono text-sm">Enter a unique identifier for your node to be discoverable on the network.</p>
            <input 
              type="text" 
              placeholder="Enter Username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              className="w-full bg-gruvbox-bg-hard border-2 border-gruvbox-fg p-4 text-gruvbox-fg-bright font-mono text-xl outline-none focus:border-gruvbox-green-bright mb-6"
            />
            <button 
              onClick={async () => {
                if(!username.trim()) return;
                try {
                  await fetch('http://127.0.0.1:8000/api/set-username', {
                     method: 'POST',
                     headers: { 'Content-Type': 'application/json' },
                     body: JSON.stringify({ username: username.trim() })
                  });
                  localStorage.setItem("qkd_username", username.trim());
                  setIsUsernameSet(true);
                  showToast(`Node Initialized as [ ${username.trim()} ]`, 'success');
                } catch (e) {
                  showToast("Failed to set username", 'error');
                }
              }}
              className="w-full bg-gruvbox-green-bright hover:bg-gruvbox-fg-bright text-gruvbox-bg-hard font-black font-mono py-3 uppercase tracking-widest transition-colors"
            >
              Initialize Node
            </button>
          </div>
        </div>
      )}
      {incomingRequest && (
        <div className="fixed inset-0 bg-black/80 z-[100] flex items-center justify-center p-4">
          <div className="bg-gruvbox-bg border-4 border-gruvbox-yellow-bright p-8 max-w-lg w-full" style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-yellow-bright)' }}>
            <h2 className="text-3xl font-black text-gruvbox-yellow-bright uppercase tracking-tighter mb-4">
              Incoming Transmission!
            </h2>
            <div className="bg-gruvbox-bg-hard border-2 border-gruvbox-bg-soft p-4 font-mono text-sm text-gruvbox-fg mb-6">
              <p className="mb-2"><span className="text-gruvbox-fg-bright font-bold">NODE IP:</span> {incomingRequest.data.sender_ip}</p>
              <p className="mb-2"><span className="text-gruvbox-fg-bright font-bold">FILE:</span> {incomingRequest.data.filename}</p>
              <p><span className="text-gruvbox-fg-bright font-bold">SIZE:</span> {incomingRequest.data.file_size} bytes</p>
            </div>
            <div className="flex justify-end gap-4">
              <button 
                onClick={async () => {
                  await fetch('http://127.0.0.1:8000/api/respond-transfer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ transfer_id: incomingRequest.transfer_id, accept: false })
                  })
                  setIncomingRequest(null)
                  showToast("Transmission Rejected.", 'error')
                }}
                className="bg-gruvbox-red-bright hover:bg-gruvbox-red-dark text-gruvbox-bg-hard font-black font-mono py-2 px-4 uppercase tracking-widest transition-colors"
              >
                Reject
              </button>
              <button 
                onClick={async () => {
                  await fetch('http://127.0.0.1:8000/api/respond-transfer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ transfer_id: incomingRequest.transfer_id, accept: true })
                  })
                  setIncomingRequest(null)
                  showToast("Transmission Accepted. Receiver Initialized.", 'success')
                }}
                className="bg-gruvbox-green-bright hover:bg-gruvbox-fg-bright text-gruvbox-bg-hard font-black font-mono py-2 px-4 uppercase tracking-widest transition-colors"
              >
                Accept
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div className={`fixed bottom-6 right-6 p-4 border-2 font-mono font-bold uppercase tracking-widest z-50 ${toast.type === 'error' ? 'bg-gruvbox-red-bright border-gruvbox-bg-soft text-gruvbox-bg-hard' : 'bg-gruvbox-green-bright border-gruvbox-bg-soft text-gruvbox-bg-hard'}`} style={{ boxShadow: '4px 4px 0 var(--color-gruvbox-fg-bright)' }}>
          {toast.message}
        </div>
      )}

      <div className="fixed top-4 right-4 flex items-center gap-2 px-3 py-1.5 border-2 border-gruvbox-bg-soft bg-gruvbox-bg z-40">
        <div className={`w-2 h-2 ${status.startsWith('CONNECTED') ? 'bg-gruvbox-green-bright shadow-[0_0_8px_var(--color-gruvbox-green-bright)]' : 'bg-gruvbox-red-bright animate-pulse'}`}></div>
        <span className="font-mono text-xs font-bold text-gruvbox-fg-bright tracking-widest">
          {status.startsWith('CONNECTED') ? 'BACKEND ONLINE' : 'BACKEND OFFLINE'}
        </span>
      </div>

      <div className="w-full max-w-3xl mb-12">
        <h1 className="text-6xl font-black text-gruvbox-orange-bright tracking-tighter uppercase mb-2">
          QKD NODE
        </h1>
        <p className="text-xl font-mono font-black text-gruvbox-yellow-bright tracking-widest uppercase">
          ID: {username || "INITIALIZING..."}
        </p>
      </div>

      <div className="w-full max-w-3xl bg-gruvbox-bg border-4 border-gruvbox-fg-bright p-8 mb-8" style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-fg-bright)' }}>
        <h2 className="text-3xl font-black text-gruvbox-fg-bright uppercase tracking-tighter mb-4">
          Select Payload
        </h2>
        <input 
          type="file" 
          onChange={(e) => setSelectedFile(e.target.files[0])}
          className="w-full bg-gruvbox-bg-hard border-2 border-gruvbox-bg-soft p-4 text-gruvbox-fg-bright font-mono file:mr-4 file:py-2 file:px-4 file:border-0 file:text-sm file:font-black file:bg-gruvbox-orange-bright file:text-gruvbox-bg-hard hover:file:bg-gruvbox-fg-bright cursor-pointer"
        />
        {selectedFile && (
          <p className="mt-4 text-gruvbox-green-bright font-mono font-bold text-sm uppercase">
            [ READY TO TRANSMIT: {selectedFile.name} ]
          </p>
        )}
      </div>

      {logs.length > 0 && (
        <div className="w-full max-w-3xl bg-gruvbox-bg border-4 border-gruvbox-fg-bright p-6 mb-8" style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-fg-bright)' }}>
          <div className="flex justify-between items-end mb-4 border-b-4 border-gruvbox-bg-soft pb-2">
            <h2 className="text-2xl font-black text-gruvbox-fg-bright uppercase tracking-tighter">
              Transfer Terminal
            </h2>
          </div>
          
          {transferProgress !== null && (
            <div className="w-full bg-gruvbox-bg-hard border-2 border-gruvbox-bg-soft mb-4">
              <div 
                className="bg-gruvbox-green-bright h-4 transition-all duration-300" 
                style={{ width: `${transferProgress}%` }}
              />
            </div>
          )}
          
          <div className="bg-gruvbox-bg-hard p-4 h-64 overflow-y-auto font-mono text-sm text-gruvbox-green-bright border-2 border-gruvbox-bg-soft flex flex-col-reverse">
            <div>
              {logs.map((log, idx) => (
                <div key={idx} className="mb-1 leading-tight">{log}</div>
              ))}
            </div>
          </div>
        </div>
      )}

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
                <button 
                  onClick={() => handleConnect(peer)}
                  className="bg-gruvbox-green-bright hover:bg-gruvbox-fg-bright text-gruvbox-bg-hard font-black font-mono py-3 px-6 transition-colors uppercase tracking-widest"
                >
                  Initiate QKD & Transfer
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
