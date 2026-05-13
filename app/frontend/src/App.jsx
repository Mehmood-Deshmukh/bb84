import React, { useState, useEffect, useRef } from 'react'
import PixelBlast from './components/PixelBlast'
import DecryptedText from './components/DecryptedText'

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
  const [history, setHistory] = useState([])
  const [isTransferActive, setIsTransferActive] = useState(false)
  const [isTerminalMinimized, setIsTerminalMinimized] = useState(false)
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
            setIsTransferActive(false)
            setTimeout(() => {
              setTransferProgress(null)
              setIsTerminalMinimized(true)
            }, 3000)
          } else if (data.message.includes("Starting transfer") || data.message.includes("Receiver launched") || data.message.includes("Starting Receiver")) {
            setTransferProgress(0)
            isTransferringRef.current = true
            setIsTransferActive(true)
            setIsTerminalMinimized(false)
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
        reconnectTimeout = setTimeout(connectWebSocket, 2000)
      }

      setSocket(ws)
    }

    connectWebSocket()

    const storedUser = localStorage.getItem("qkd_username")
    if (storedUser) {
      fetch('http://127.0.0.1:8000/api/set-username', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: storedUser })
      }).catch(err => console.error(err))
    }

    const fetchPeers = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/peers')
        const data = await response.json()
        setPeers(data.peers || [])
      } catch (err) {
        console.error("Failed to fetch peers", err)
      }
    }

    const fetchHistory = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/history')
        const data = await response.json()
        setHistory(data.history || [])
      } catch (err) {}
    }

    fetchPeers()
    fetchHistory()
    const interval = setInterval(() => {
      fetchPeers()
      fetchHistory()
    }, 2000)

    return () => {
      if (ws) ws.close()
      clearTimeout(reconnectTimeout)
      clearInterval(interval)
    }
  }, [])

  const isOnline = status.startsWith('CONNECTED')

  return (
    <>
      <div className="fixed top-[20%] inset-0 z-0 pointer-events-auto opacity-60">
        <PixelBlast
          variant="square"
          pixelSize={4}
          color="#fe8019"
          patternScale={2}
          patternDensity={0.15}
          pixelSizeJitter={0}
          enableRipples
          rippleSpeed={0.4}
          rippleThickness={0.12}
          rippleIntensityScale={1.5}
          liquid={false}
          liquidStrength={0.12}
          liquidRadius={1.2}
          liquidWobbleSpeed={5}
          speed={0.5}
          edgeFade={0.25}
          transparent
        />
      </div>

      {!isUsernameSet && (
        <div className="fixed inset-0 bg-black/92 z-[200] flex items-center justify-center p-4">
          <div
            className="bg-gruvbox-bg border-4 border-gruvbox-yellow-bright p-10 max-w-md w-full"
            style={{ boxShadow: '10px 10px 0 var(--color-gruvbox-yellow-bright)' }}
          >
            <div className="w-12 h-1 bg-gruvbox-orange-bright mb-4" />
            <h2 className="text-4xl font-black text-gruvbox-yellow-bright uppercase tracking-tighter mb-2">
              Identify Node
            </h2>
            <p className="text-gruvbox-fg font-mono text-sm mb-8 leading-relaxed">
              Assign a unique identifier to your node before joining the quantum network.
            </p>
            <input
              type="text"
              placeholder="NODE IDENTIFIER"
              value={username}
              onChange={e => setUsername(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && username.trim() && (() => {
                fetch('http://127.0.0.1:8000/api/set-username', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ username: username.trim() })
                }).catch(() => { })
                localStorage.setItem("qkd_username", username.trim())
                setIsUsernameSet(true)
                showToast(`Node Initialized as [ ${username.trim()} ]`, 'success')
              })()}
              className="w-full bg-gruvbox-bg-hard border-2 border-gruvbox-fg p-4 text-gruvbox-fg-bright font-mono text-lg outline-none focus:border-gruvbox-green-bright mb-6 placeholder:text-gruvbox-fg/40 tracking-widest"
            />
            <button
              onClick={async () => {
                if (!username.trim()) return;
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
              className="w-full bg-gruvbox-green-bright hover:bg-gruvbox-fg-bright text-gruvbox-bg-hard font-black font-mono py-3.5 uppercase tracking-widest transition-colors text-sm"
            >
              Initialize Node →
            </button>
          </div>
        </div>
      )}

      {incomingRequest && (
        <div className="fixed inset-0 bg-black/85 z-[100] flex items-center justify-center p-4">
          <div
            className="bg-gruvbox-bg border-4 border-gruvbox-yellow-bright p-10 max-w-lg w-full"
            style={{ boxShadow: '10px 10px 0 var(--color-gruvbox-yellow-bright)' }}
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="w-3 h-3 bg-gruvbox-yellow-bright animate-pulse" />
              <span className="text-gruvbox-yellow-bright font-mono text-xs tracking-[0.3em] font-bold">INCOMING TRANSMISSION</span>
            </div>
            <h2 className="text-4xl font-black text-gruvbox-fg-bright uppercase tracking-tighter mb-6">
              Accept Transfer?
            </h2>
            <div className="bg-gruvbox-bg-hard border-l-4 border-gruvbox-orange-bright p-5 font-mono text-sm text-gruvbox-fg mb-8 space-y-2">
              <div className="flex gap-3">
                <span className="text-gruvbox-fg/60 w-20 shrink-0">SOURCE</span>
                <span className="text-gruvbox-fg-bright font-bold">{incomingRequest.data.sender_ip}</span>
              </div>
              <div className="flex gap-3">
                <span className="text-gruvbox-fg/60 w-20 shrink-0">FILE</span>
                <span className="text-gruvbox-fg-bright font-bold break-all">{incomingRequest.data.filename}</span>
              </div>
              <div className="flex gap-3">
                <span className="text-gruvbox-fg/60 w-20 shrink-0">SIZE</span>
                <span className="text-gruvbox-fg-bright font-bold">{(incomingRequest.data.file_size / 1024).toFixed(1)} KB</span>
              </div>
            </div>
            <div className="flex gap-4">
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
                className="flex-1 bg-transparent border-2 border-gruvbox-red-bright hover:bg-gruvbox-red-bright text-gruvbox-red-bright hover:text-gruvbox-bg-hard font-black font-mono py-3 uppercase tracking-widest transition-all text-sm"
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
                className="flex-1 bg-gruvbox-green-bright hover:bg-gruvbox-fg-bright text-gruvbox-bg-hard font-black font-mono py-3 uppercase tracking-widest transition-colors text-sm"
              >
                Accept →
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div
          className={`fixed bottom-6 right-6 p-4 border-2 font-mono font-bold uppercase tracking-widest z-50 text-sm max-w-sm ${toast.type === 'error'
              ? 'bg-gruvbox-red-bright border-gruvbox-bg-hard text-gruvbox-bg-hard'
              : 'bg-gruvbox-green-bright border-gruvbox-bg-hard text-gruvbox-bg-hard'
            }`}
          style={{ boxShadow: '4px 4px 0 rgba(0,0,0,0.5)' }}
        >
          {toast.message}
        </div>
      )}

      {/* Status Badge */}
      <div className="fixed top-5 right-5 flex items-center gap-2 px-4 py-2 border-2 border-gruvbox-bg-soft bg-gruvbox-bg/95 z-40 backdrop-blur-sm">
        <div className={`w-2 h-2 rounded-full ${isOnline ? 'bg-gruvbox-green-bright shadow-[0_0_8px_var(--color-gruvbox-green-bright)]' : 'bg-gruvbox-red-bright animate-pulse'}`} />
        <span className="font-mono text-xs font-bold text-gruvbox-fg-bright tracking-[0.2em]">
          {isOnline ? 'BACKEND ONLINE' : 'BACKEND OFFLINE'}
        </span>
      </div>

      <div className="flex flex-col items-center min-h-screen w-full relative z-10 pointer-events-none">
        <div className="pointer-events-auto w-full max-w-3xl px-6 pt-16 pb-20 flex flex-col gap-8">

          <div className="mb-4">
            {/* <div className="flex items-center gap-3 mb-5">
              <div className="h-px flex-1 bg-gruvbox-orange-bright/40" />
              <span className="font-mono text-xs text-gruvbox-orange-bright tracking-[0.4em] font-bold">
                QUANTUM KEY DISTRIBUTION
              </span>
              <div className="h-px flex-1 bg-gruvbox-orange-bright/40" />
            </div> */}

            <div className="leading-none mb-1">
              <div className="text-[clamp(2rem,6vw,4rem)] font-black text-gruvbox-fg-bright uppercase tracking-tighter leading-none">
                <DecryptedText text="FILE TRANSFER" speed={50} maxIterations={18} />
              </div>
              <div className="text-[clamp(1.5rem,4vw,2.5rem)] font-black uppercase tracking-tighter leading-none" style={{ WebkitTextStroke: '1.5px var(--color-gruvbox-orange-bright)', color: 'transparent' }}>
                <DecryptedText text="USING BB84 QKD" speed={55} maxIterations={22} />
              </div>
            </div>

            <div className="flex items-center gap-4 mt-5">
              <div className="w-8 h-1 bg-gruvbox-yellow-bright" />
              <span className="font-mono font-black text-gruvbox-yellow-bright tracking-widest text-sm uppercase">
                Node: {username || <span className="opacity-40">INITIALIZING…</span>}
              </span>
            </div>
          </div>

          <section
            className="bg-gruvbox-bg border-4 border-gruvbox-fg-bright p-7"
            style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-fg-bright)' }}
          >
            <div className="flex items-center gap-3 mb-5">
              <span className="text-gruvbox-orange-bright font-mono text-xs font-bold tracking-[0.3em]">01 /</span>
              <h2 className="text-2xl font-black text-gruvbox-fg-bright uppercase tracking-tighter">Select Payload</h2>
            </div>
            <label className={`block w-full bg-gruvbox-bg-hard border-2 border-dashed border-gruvbox-bg-soft transition-colors p-6 text-center group ${isTransferActive ? 'opacity-50 cursor-not-allowed' : 'hover:border-gruvbox-orange-bright cursor-pointer'}`}>
              <input
                type="file"
                disabled={isTransferActive}
                onChange={(e) => setSelectedFile(e.target.files[0])}
                className="hidden"
              />
              {selectedFile ? (
                <div>
                  <p className="text-gruvbox-green-bright font-mono font-black text-sm uppercase tracking-widest mb-1">
                    ✓ Ready to Transmit
                  </p>
                  <p className="text-gruvbox-fg-bright font-mono text-base font-bold break-all">
                    {selectedFile.name}
                  </p>
                  <p className="text-gruvbox-fg/60 font-mono text-xs mt-1">
                    {(selectedFile.size / 1024).toFixed(1)} KB — click to change
                  </p>
                </div>
              ) : (
                <div>
                  <p className="text-gruvbox-fg/50 font-mono text-sm uppercase tracking-widest group-hover:text-gruvbox-orange-bright transition-colors">
                    Click to select file
                  </p>
                </div>
              )}
            </label>
          </section>

          {logs.length > 0 && (
            <section
              className="bg-gruvbox-bg border-4 border-gruvbox-fg-bright p-7 transition-all duration-300"
              style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-fg-bright)' }}
            >
              <div
                className="flex items-center gap-3 mb-5 cursor-pointer group"
                onClick={() => setIsTerminalMinimized(!isTerminalMinimized)}
              >
                <span className="text-gruvbox-orange-bright font-mono text-xs font-bold tracking-[0.3em]">02 /</span>
                <h2 className="text-2xl font-black text-gruvbox-fg-bright uppercase tracking-tighter">
                  Transfer Terminal
                </h2>

                <span className="ml-auto font-mono text-xs text-gruvbox-fg/40 group-hover:text-gruvbox-fg/80 transition-colors uppercase tracking-widest">
                  [{isTerminalMinimized ? 'EXPAND' : 'COLLAPSE'}]
                </span>

                {transferProgress !== null && !isTerminalMinimized && (
                  <span className="ml-4 font-mono text-xs font-bold text-gruvbox-green-bright tracking-widest">
                    {transferProgress.toFixed(0)}%
                  </span>
                )}
              </div>

              {!isTerminalMinimized && (
                <>
                  {transferProgress !== null && (
                    <div className="w-full bg-gruvbox-bg-hard border border-gruvbox-bg-soft mb-5 h-2 overflow-hidden">
                      <div
                        className="bg-gruvbox-green-bright h-full transition-all duration-300 relative"
                        style={{ width: `${transferProgress}%` }}
                      >
                        <div className="absolute inset-0 bg-white/20 animate-pulse" />
                      </div>
                    </div>
                  )}

                  <div className="bg-gruvbox-bg-hard border border-gruvbox-bg-soft h-56 overflow-y-auto font-mono text-xs text-gruvbox-green-bright p-4 flex flex-col-reverse">
                    <div>
                      {logs.map((log, idx) => (
                        <div key={idx} className="mb-1 leading-relaxed opacity-90">
                          <span className="text-gruvbox-fg/40 mr-2 select-none">{String(idx + 1).padStart(3, '0')}</span>
                          {log}
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </section>
          )}

          {history.length > 0 && (
            <section
              className="bg-gruvbox-bg border-4 border-gruvbox-fg-bright p-7 mb-8"
              style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-fg-bright)' }}
            >
              <div className="flex items-center gap-3 mb-5">
                <span className="text-gruvbox-orange-bright font-mono text-xs font-bold tracking-[0.3em]">H /</span>
                <h2 className="text-2xl font-black text-gruvbox-fg-bright uppercase tracking-tighter">
                  Transfer History
                </h2>
              </div>
              <div className="flex flex-col gap-3">
                {history.map((item, idx) => (
                  <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between bg-gruvbox-bg-hard border-2 border-gruvbox-bg-soft p-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`font-mono text-[10px] tracking-widest font-bold px-2 py-0.5 text-gruvbox-bg-hard ${item.type === 'SENT' ? 'bg-gruvbox-blue-bright' : 'bg-gruvbox-purple-bright'}`}>
                          {item.type}
                        </span>
                        <span className="font-mono text-[10px] text-gruvbox-fg/60 tracking-widest">
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <h3 className="font-black text-gruvbox-fg-bright text-base break-words">
                        {item.filename}
                      </h3>
                      <p className="text-gruvbox-fg/70 font-mono text-xs mt-1">
                        Peer: {item.peer_ip} | Status: <span className="text-gruvbox-green-bright">{item.status}</span>
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          <section
            className="bg-gruvbox-bg border-4 border-gruvbox-fg-bright p-7 sticky top-6 z-20"
            style={{ boxShadow: '8px 8px 0 var(--color-gruvbox-fg-bright)' }}
          >
            <div className="flex items-end justify-between mb-6 pb-4 border-b-4 border-gruvbox-bg-soft">
              <div className="flex items-center gap-3">
                <span className="text-gruvbox-orange-bright font-mono text-xs font-bold tracking-[0.3em]">03 /</span>
                <h2 className="text-2xl font-black text-gruvbox-fg-bright uppercase tracking-tighter">
                  Discovered Peers
                </h2>
              </div>
              <div className="flex items-center gap-2 bg-gruvbox-blue-bright px-3 py-1">
                <div className="w-1.5 h-1.5 bg-gruvbox-bg-hard rounded-full" />
                <span className="text-gruvbox-bg-hard font-mono font-black text-xs tracking-widest">
                  {peers.length} ONLINE
                </span>
              </div>
            </div>

            {peers.length === 0 ? (
              <div className="py-14 flex flex-col items-center gap-4 bg-gruvbox-bg-soft border-2 border-gruvbox-bg-hard">
                {/* Animated scan bars */}
                <div className="flex gap-1 items-end h-8">
                  {[1, 2, 3, 4, 5].map(i => (
                    <div
                      key={i}
                      className="w-1.5 bg-gruvbox-orange-bright/60 animate-pulse"
                      style={{
                        height: `${20 + Math.sin(i) * 12}px`,
                        animationDelay: `${i * 0.15}s`
                      }}
                    />
                  ))}
                </div>
                <p className="text-gruvbox-fg font-mono font-bold text-sm tracking-[0.25em] uppercase">
                  Scanning Local Network…
                </p>
              </div>
            ) : (
              <div className="flex flex-col gap-4">
                {peers.map((peer, i) => (
                  <div
                    key={i}
                    className="flex flex-col sm:flex-row sm:items-center justify-between bg-gruvbox-bg-hard border-2 border-gruvbox-bg-soft hover:border-gruvbox-orange-bright transition-all p-5 group"
                  >
                    <div className="mb-4 sm:mb-0">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="w-1.5 h-1.5 bg-gruvbox-green-bright rounded-full shadow-[0_0_6px_var(--color-gruvbox-green-bright)]" />
                        <span className="font-mono text-xs text-gruvbox-green-bright tracking-widest font-bold">ACTIVE</span>
                      </div>
                      <h3 className="font-black text-gruvbox-fg-bright text-xl uppercase tracking-tighter group-hover:text-gruvbox-orange-bright transition-colors">
                        {peer.name}
                      </h3>
                      <p className="text-gruvbox-fg/70 font-mono text-xs mt-1 tracking-widest">
                        {peer.ip}:{peer.port}
                      </p>
                    </div>
                    <button
                      onClick={() => handleConnect(peer)}
                      disabled={isTransferActive}
                      className={`border-2 py-3 px-5 transition-all uppercase tracking-widest text-sm whitespace-nowrap font-black font-mono ${isTransferActive
                          ? 'border-gruvbox-fg/20 text-gruvbox-fg/40 cursor-not-allowed bg-transparent'
                          : 'bg-transparent border-gruvbox-green-bright text-gruvbox-green-bright hover:bg-gruvbox-green-bright hover:text-gruvbox-bg-hard'
                        }`}
                    >
                      {isTransferActive ? 'TRANSFERRING...' : 'Initiate Transfer →'}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </section>

        </div>
      </div>
    </>
  )
}

export default App