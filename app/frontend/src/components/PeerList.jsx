import { useEffect, useState } from 'react'
import { forgetPeer, verifyPeer } from '../api/client'

const STORAGE_KEY = 'qkd_known_peer_fingerprints'

function getStoredFingerprints() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}')
  } catch {
    return {}
  }
}

function saveStoredFingerprints(map) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(map))
  } catch {
    // Ignore storage errors (e.g. private mode or disabled storage)
  }
}

function TrustBadge({ trust }) {
  if (trust === 'verified') {
    return (
      <span className="inline-flex items-center gap-1 rounded-sm border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-fine font-medium text-accent">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="shrink-0" aria-hidden="true">
          <path d="M2.5 6.5 4.5 8.5 9.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span>Verified</span>
      </span>
    )
  }
  if (trust === 'pinned') {
    return (
      <span className="inline-flex items-center gap-1 rounded-sm border border-rule bg-well px-1.5 py-0.5 text-fine font-medium text-ink">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="shrink-0" aria-hidden="true">
          <circle cx="6" cy="6" r="3" fill="currentColor" />
        </svg>
        <span>Pinned</span>
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-sm border border-rule bg-surface px-1.5 py-0.5 text-fine font-medium text-ink-2">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="shrink-0" aria-hidden="true">
        <circle cx="6" cy="6" r="3.5" stroke="currentColor" strokeWidth="1.2" strokeDasharray="2 2" />
      </svg>
      <span>New</span>
    </span>
  )
}

function getSecurityCopy(trust) {
  if (trust === 'verified') {
    return 'Identity verified. Cryptographic classical channel authenticated.'
  }
  if (trust === 'pinned') {
    return 'Key recorded on first contact. Confirm fingerprint with peer before sending sensitive files.'
  }
  return "This peer's key hasn't been confirmed — verify the fingerprint before sending sensitive files."
}

/** Radio list of discovered peers with trust badges and fingerprint verification. */
export default function PeerList({ peers, selectedId, onSelect, loading }) {
  const [storedFingerprints, setStoredFingerprints] = useState(getStoredFingerprints)
  const [trustOverrides, setTrustOverrides] = useState({})
  const [actionLoading, setActionLoading] = useState(null)
  const [actionError, setActionError] = useState({})
  const [actionSuccess, setActionSuccess] = useState({})
  const [copiedId, setCopiedId] = useState(null)

  useEffect(() => {
    if (!peers?.length) return
    let updated = false
    const nextStored = { ...storedFingerprints }
    for (const peer of peers) {
      if (peer.fingerprint && !nextStored[peer.id]) {
        nextStored[peer.id] = peer.fingerprint
        updated = true
      }
    }
    if (updated) {
      setStoredFingerprints(nextStored)
      saveStoredFingerprints(nextStored)
    }
  }, [peers, storedFingerprints])

  const handleVerify = async (peer) => {
    setActionLoading(peer.id)
    setActionError((prev) => ({ ...prev, [peer.id]: null }))
    setActionSuccess((prev) => ({ ...prev, [peer.id]: null }))
    try {
      await verifyPeer(peer.id)
      setTrustOverrides((prev) => ({ ...prev, [peer.id]: 'verified' }))
      setActionSuccess((prev) => ({ ...prev, [peer.id]: 'Marked verified' }))
      if (peer.fingerprint) {
        const updated = { ...storedFingerprints, [peer.id]: peer.fingerprint }
        setStoredFingerprints(updated)
        saveStoredFingerprints(updated)
      }
      setTimeout(() => {
        setActionSuccess((prev) => ({ ...prev, [peer.id]: null }))
      }, 3000)
    } catch (err) {
      setActionError((prev) => ({ ...prev, [peer.id]: err.message || 'Failed to verify peer' }))
    } finally {
      setActionLoading(null)
    }
  }

  const handleForget = async (peer) => {
    setActionLoading(peer.id)
    setActionError((prev) => ({ ...prev, [peer.id]: null }))
    setActionSuccess((prev) => ({ ...prev, [peer.id]: null }))
    try {
      await forgetPeer(peer.id)
      setTrustOverrides((prev) => ({ ...prev, [peer.id]: 'new' }))
      setActionSuccess((prev) => ({ ...prev, [peer.id]: 'Trust reset' }))
      const updated = { ...storedFingerprints }
      delete updated[peer.id]
      setStoredFingerprints(updated)
      saveStoredFingerprints(updated)
      setTimeout(() => {
        setActionSuccess((prev) => ({ ...prev, [peer.id]: null }))
      }, 3000)
    } catch (err) {
      setActionError((prev) => ({ ...prev, [peer.id]: err.message || 'Failed to forget peer' }))
    } finally {
      setActionLoading(null)
    }
  }

  const handleAcceptKey = (peer) => {
    const updated = { ...storedFingerprints, [peer.id]: peer.fingerprint }
    setStoredFingerprints(updated)
    saveStoredFingerprints(updated)
  }

  const copyFingerprint = async (peerId, fp) => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(fp)
      }
    } catch {
      // Ignore clipboard write failure
    }
    setCopiedId(peerId)
    setTimeout(() => setCopiedId(null), 2000)
  }

  if (!peers.length) {
    return (
      <p className="text-small text-ink-2">
        {loading
          ? 'Looking for peers on this network…'
          : 'No peers found yet. Start qkd-node on another machine on the same network and it appears here within a few seconds.'}
      </p>
    )
  }

  return (
    <ul className="divide-y divide-rule border-y border-rule">
      {peers.map((peer) => {
        const previousFp = storedFingerprints[peer.id]
        const keyChanged = Boolean(previousFp && peer.fingerprint && previousFp !== peer.fingerprint)
        const effectiveTrust = trustOverrides[peer.id] ?? peer.trust ?? 'new'
        const selectable = peer.reachable && !keyChanged

        return (
          <li key={peer.id} className="space-y-2 px-1 py-3">
            <div className="flex items-start justify-between gap-3">
              <label
                className={`flex min-w-0 flex-1 items-start gap-3 ${
                  selectable ? 'cursor-pointer hover:text-accent' : 'cursor-not-allowed text-ink-2'
                }`}
              >
                <input
                  type="radio"
                  name="peer"
                  value={peer.id}
                  checked={selectedId === peer.id}
                  onChange={() => selectable && onSelect(peer.id)}
                  disabled={!selectable}
                  className="mt-1 size-4 accent-(--color-accent)"
                />
                <span className="min-w-0">
                  <span className="block truncate font-medium">{peer.name}</span>
                  <span translate="no" className="block font-mono text-small text-ink-2">
                    {peer.host}:{peer.port}
                    {peer.reachable ? '' : ', not responding'}
                  </span>
                </span>
              </label>
              <TrustBadge trust={effectiveTrust} />
            </div>

            {keyChanged ? (
              <div role="alert" className="rounded-sm border border-danger bg-danger/10 p-2.5 text-small text-danger">
                <div className="flex items-center gap-1.5 font-semibold">
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="shrink-0" aria-hidden="true">
                    <path d="M7 1.5 12.5 11.5H1.5L7 1.5Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                    <path d="M7 5.5v3M7 10h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  <span>SECURITY WARNING: Identity Key Changed!</span>
                </div>
                <p className="mt-1 text-fine text-ink">
                  The security key advertised by <strong>{peer.name}</strong> does not match the key previously recorded.
                  This may indicate an active Man-in-the-Middle attack. Transfers to this peer are blocked until confirmed.
                </p>
                <div className="mt-2 space-y-0.5 font-mono text-fine">
                  <div className="flex gap-2">
                    <span className="text-ink-2">Previous:</span>
                    <span className="select-all truncate text-ink">{previousFp}</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-ink-2">Current:</span>
                    <span className="select-all truncate text-ink">{peer.fingerprint}</span>
                  </div>
                </div>
                <div className="mt-2.5">
                  <button
                    type="button"
                    onClick={() => handleAcceptKey(peer)}
                    className="rounded-sm bg-danger px-2.5 py-1 text-fine font-medium text-white hover:bg-danger/85"
                  >
                    Accept new key
                  </button>
                </div>
              </div>
            ) : null}

            {peer.fingerprint ? (
              <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5 pl-7 text-fine">
                <div className="flex items-center gap-1.5 text-ink-2">
                  <span>FP:</span>
                  <span translate="no" className="select-all font-mono text-ink break-all">{peer.fingerprint}</span>
                  <button
                    type="button"
                    onClick={() => copyFingerprint(peer.id, peer.fingerprint)}
                    title="Copy peer fingerprint to clipboard"
                    aria-label={`Copy fingerprint for ${peer.name}`}
                    className="rounded border border-rule bg-surface px-1.5 py-0.5 text-fine text-ink-2 hover:bg-well hover:text-ink"
                  >
                    {copiedId === peer.id ? <span className="font-medium text-accent">Copied</span> : <span>Copy</span>}
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  {actionSuccess[peer.id] ? (
                    <span className="text-fine font-medium text-accent">{actionSuccess[peer.id]}</span>
                  ) : null}
                  {actionError[peer.id] ? (
                    <span role="alert" className="text-fine text-danger">{actionError[peer.id]}</span>
                  ) : null}

                  {effectiveTrust !== 'verified' ? (
                    <button
                      type="button"
                      disabled={actionLoading === peer.id}
                      onClick={() => handleVerify(peer)}
                      className="rounded-sm border border-rule bg-surface px-2 py-0.5 text-fine text-ink hover:border-ink-2 disabled:opacity-50"
                    >
                      {actionLoading === peer.id ? 'Updating…' : 'Mark verified'}
                    </button>
                  ) : null}

                  {effectiveTrust !== 'new' ? (
                    <button
                      type="button"
                      disabled={actionLoading === peer.id}
                      onClick={() => handleForget(peer)}
                      className="rounded-sm border border-rule bg-surface px-2 py-0.5 text-fine text-ink-2 hover:border-danger hover:text-danger disabled:opacity-50"
                    >
                      {actionLoading === peer.id ? 'Updating…' : 'Forget'}
                    </button>
                  ) : null}
                </div>
              </div>
            ) : null}

            {!keyChanged ? (
              <p className="pl-7 text-fine text-ink-2">
                {getSecurityCopy(effectiveTrust)}
              </p>
            ) : null}
          </li>
        )
      })}
    </ul>
  )
}
