import { useMemo, useState } from 'react'
import { createTransfer, renameNode, respondToTransfer } from './api/client'
import { ACTIVE_STATUSES, TERMINAL_STATUSES } from './api/types'
import { useHistory, useNode, usePeers, useTransfers } from './hooks/useNodeState'
import { useTransferEvents } from './hooks/useTransferEvents'

function App() {
  const node = useNode()
  const peers = usePeers().data ?? []
  const transfers = useTransfers()
  const history = useHistory().data ?? []
  const [selectedFile, setSelectedFile] = useState(null)
  const [toast, setToast] = useState(null)
  const [username, setUsername] = useState(localStorage.getItem("qkd_username") || "")
  const [isUsernameSet, setIsUsernameSet] = useState(!!localStorage.getItem("qkd_username"))
  const [isTerminalMinimized, setIsTerminalMinimized] = useState(false)

  const allTransfers = useMemo(() => transfers.data ?? [], [transfers.data])
  const incomingRequest = allTransfers.find(t => t.direction === 'incoming' && t.status === 'pending')
  const activeTransfer = allTransfers.find(t => ACTIVE_STATUSES.has(t.status))
    ?? allTransfers.find(t => t.status !== 'pending')
  const events = useTransferEvents(activeTransfer?.id ?? null)
  const logs = events.filter(e => e.type === 'log').map(e => e.payload.message)
  const isTransferActive = !!activeTransfer && ACTIVE_STATUSES.has(activeTransfer.status)
  const progress = activeTransfer?.progress
  const transferProgress = progress && progress.num_chunks > 0 && !TERMINAL_STATUSES.has(activeTransfer.status)
    ? (progress.chunks_done / progress.num_chunks) * 100
    : null

  const showToast = (message, type = 'info') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4000)
  }

  const saveUsername = async () => {
    const name = username.trim()
    if (!name) return
    try {
      await renameNode(name)
      localStorage.setItem("qkd_username", name)
      setIsUsernameSet(true)
      showToast(`Node Initialized as [ ${name} ]`, 'success')
    } catch (err) {
      showToast(`Failed to set username: ${err.message}`, 'error')
    }
  }

  const handleConnect = async (peer) => {
    if (!selectedFile) {
      showToast("[ ERROR ] PLEASE SELECT A FILE TO TRANSMIT FIRST.", 'error')
      return
    }
    try {
      await createTransfer(selectedFile, peer.id)
      transfers.refresh()
      showToast("[ SUCCESS ] Request sent to peer. Waiting for acceptance...", 'success')
    } catch (err) {
      showToast("[ ERROR ] " + err.message, 'error')
    }
  }

  const respond = async (status) => {
    try {
      await respondToTransfer(incomingRequest.id, status)
      transfers.refresh()
      showToast(status === 'accepted' ? "Transmission Accepted. Receiver Initialized." : "Transmission Rejected.",
        status === 'accepted' ? 'success' : 'error')
    } catch (err) {
      showToast("[ ERROR ] " + err.message, 'error')
    }
  }

  const isOnline = !node.error && !!node.data

  return (
    <>

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
              onKeyDown={e => e.key === 'Enter' && saveUsername()}
              className="w-full bg-gruvbox-bg-hard border-2 border-gruvbox-fg p-4 text-gruvbox-fg-bright font-mono text-lg outline-none focus:border-gruvbox-green-bright mb-6 placeholder:text-gruvbox-fg/40 tracking-widest"
            />
            <button
              onClick={saveUsername}
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
                <span className="text-gruvbox-fg-bright font-bold">{incomingRequest.peer.name} ({incomingRequest.peer.host})</span>
              </div>
              <div className="flex gap-3">
                <span className="text-gruvbox-fg/60 w-20 shrink-0">FILE</span>
                <span className="text-gruvbox-fg-bright font-bold break-all">{incomingRequest.filename}</span>
              </div>
              <div className="flex gap-3">
                <span className="text-gruvbox-fg/60 w-20 shrink-0">SIZE</span>
                <span className="text-gruvbox-fg-bright font-bold">{(incomingRequest.file_size / 1024).toFixed(1)} KB</span>
              </div>
            </div>
            <div className="flex gap-4">
              <button
                onClick={() => respond('rejected')}
                className="flex-1 bg-transparent border-2 border-gruvbox-red-bright hover:bg-gruvbox-red-bright text-gruvbox-red-bright hover:text-gruvbox-bg-hard font-black font-mono py-3 uppercase tracking-widest transition-all text-sm"
              >
                Reject
              </button>
              <button
                onClick={() => respond('accepted')}
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

            <div className="leading-none mb-1">
              <div className="text-[clamp(2rem,6vw,4rem)] font-black text-gruvbox-fg-bright uppercase tracking-tighter leading-none">
                FILE TRANSFER
              </div>
              <div className="text-[clamp(1.5rem,4vw,2.5rem)] font-black uppercase tracking-tighter leading-none" style={{ WebkitTextStroke: '1.5px var(--color-gruvbox-orange-bright)', color: 'transparent' }}>
                USING BB84 QKD
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
                {history.map((item) => (
                  <div key={item.id} className="flex flex-col sm:flex-row sm:items-center justify-between bg-gruvbox-bg-hard border-2 border-gruvbox-bg-soft p-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`font-mono text-[10px] tracking-widest font-bold px-2 py-0.5 text-gruvbox-bg-hard ${item.direction === 'outgoing' ? 'bg-gruvbox-blue-bright' : 'bg-gruvbox-purple-bright'}`}>
                          {item.direction === 'outgoing' ? 'SENT' : 'RECEIVED'}
                        </span>
                        <span className="font-mono text-[10px] text-gruvbox-fg/60 tracking-widest">
                          {new Date(item.finished_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <h3 className="font-black text-gruvbox-fg-bright text-base break-words">
                        {item.filename}
                      </h3>
                      <p className="text-gruvbox-fg/70 font-mono text-xs mt-1">
                        Peer: {item.peer_name} ({item.peer_host}) | Status: <span className="text-gruvbox-green-bright">{item.status}</span>
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
                {peers.map((peer) => (
                  <div
                    key={peer.id}
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
                        {peer.host}:{peer.port}
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