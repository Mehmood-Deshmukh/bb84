import { useRef, useState } from 'react'
import { formatBytes } from '../lib/format'
import PeerList from './PeerList'

export default function SendForm({ peers, peersLoading, onSend }) {
  const [file, setFile] = useState(null)
  const [peerId, setPeerId] = useState(null)
  const [sending, setSending] = useState(false)
  const [error, setError] = useState(null)
  const [missing, setMissing] = useState(null)
  const fileInput = useRef(null)

  const peer = peers.find((p) => p.id === peerId && p.reachable)

  const submit = async (event) => {
    event.preventDefault()
    if (sending) return
    if (!file) {
      setMissing('file')
      fileInput.current?.focus()
      return
    }
    if (!peer) {
      setMissing('peer')
      event.target.querySelector('input[name="peer"]:not(:disabled)')?.focus()
      return
    }
    setMissing(null)
    setSending(true)
    setError(null)
    try {
      await onSend(file, peer.id)
      setFile(null)
      event.target.reset()
    } catch (err) {
      setError(err.message)
    } finally {
      setSending(false)
    }
  }

  return (
    <form onSubmit={submit} aria-labelledby="send-heading" className="space-y-5">
      <h2 id="send-heading" className="text-section font-semibold">Send a file</h2>

      <div>
        <label htmlFor="file" className="mb-1.5 block text-small font-medium">File</label>
        <input
          ref={fileInput}
          id="file"
          name="file"
          type="file"
          aria-invalid={missing === 'file' || undefined}
          aria-describedby={missing === 'file' ? 'file-error' : undefined}
          onChange={(e) => {
            setFile(e.target.files?.[0] ?? null)
            setMissing(null)
          }}
          className="block w-full text-small text-ink-2 file:mr-3 file:rounded-sm file:border file:border-rule file:bg-surface file:px-3 file:py-1.5 file:text-small file:font-medium file:text-ink hover:file:border-ink-2"
        />
        {file ? <p className="mt-1 text-small text-ink-2">{formatBytes(file.size)}</p> : null}
        {missing === 'file' ? <p id="file-error" role="alert" className="mt-1 text-small text-danger">Choose a file first.</p> : null}
      </div>

      <fieldset>
        <legend className="mb-1.5 text-small font-medium">Peer</legend>
        <PeerList peers={peers} selectedId={peerId} onSelect={(id) => { setPeerId(id); setMissing(null) }} loading={peersLoading} />
        {missing === 'peer' ? (
          <p role="alert" className="mt-1 text-small text-danger">
            {peers.some((p) => p.reachable) ? 'Choose who receives the file.' : 'No reachable peer yet. Start qkd-node on another machine.'}
          </p>
        ) : null}
      </fieldset>

      <div className="space-y-2">
        <button
          type="submit"
          disabled={sending}
          className="w-full rounded-sm bg-accent px-4 py-2.5 font-medium text-on-accent hover:bg-accent/85 disabled:bg-well disabled:text-ink-2"
        >
          {sending ? 'Sending offer…' : peer ? `Send to ${peer.name}` : 'Send file'}
        </button>
        <p className="text-small text-ink-2">The peer has to accept before the key exchange starts.</p>
        {error ? <p role="alert" className="text-small text-danger">{error}</p> : null}
      </div>
    </form>
  )
}
