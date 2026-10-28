import { useState } from 'react'
import { TERMINAL_STATUSES } from '../api/types'
import { formatBytes } from '../lib/format'
import LiveLog from './LiveLog'
import ProtocolView from './ProtocolView'
import StatusLabel from './StatusLabel'

function Actions({ transfer, onRespond, onCancel, busy }) {
  if (transfer.direction === 'incoming' && transfer.status === 'pending') {
    return (
      <div className="flex flex-wrap gap-2">
        <button type="button" disabled={busy} onClick={() => onRespond(transfer.id, 'accepted')}
          className="rounded-sm bg-accent px-4 py-2 font-medium text-on-accent hover:bg-accent/85">
          Accept and receive
        </button>
        <button type="button" disabled={busy} onClick={() => onRespond(transfer.id, 'rejected')}
          className="rounded-sm border border-rule px-4 py-2 font-medium hover:border-ink-2">
          Decline
        </button>
      </div>
    )
  }
  if (TERMINAL_STATUSES.has(transfer.status)) return null
  return <CancelButton transfer={transfer} onCancel={onCancel} busy={busy} />
}

/** Cancelling stops both nodes and cannot be undone, so it takes a second click. */
function CancelButton({ transfer, onCancel, busy }) {
  const [confirming, setConfirming] = useState(false)
  if (!confirming) {
    return (
      <button type="button" disabled={busy} onClick={() => setConfirming(true)}
        className="rounded-sm border border-rule px-4 py-2 font-medium hover:border-danger hover:text-danger">
        Cancel transfer
      </button>
    )
  }
  return (
    <div role="group" aria-label="Confirm cancellation" className="flex flex-wrap items-center gap-2">
      <span className="text-small">Stop this transfer on both nodes?</span>
      <button type="button" autoFocus disabled={busy} onClick={() => onCancel(transfer.id)}
        className="rounded-sm bg-danger px-4 py-2 font-medium text-paper hover:bg-danger/85">
        Stop transfer
      </button>
      <button type="button" onClick={() => setConfirming(false)}
        className="rounded-sm border border-rule px-4 py-2 font-medium hover:border-ink-2">
        Keep going
      </button>
    </div>
  )
}

function waitingNote(transfer) {
  if (transfer.status !== 'pending') return null
  return transfer.direction === 'outgoing'
    ? `Waiting for ${transfer.peer.name} to accept. Nothing has been sent yet.`
    : `${transfer.peer.name} wants to send you this file. Nothing is received until you accept.`
}

export default function TransferPanel({ transfer, events, onRespond, onCancel, busy, actionError }) {
  if (!transfer) {
    return (
      <div className="max-w-prose space-y-2 py-8">
        <h2 className="text-section font-semibold">No transfer selected</h2>
        <p className="text-ink-2">
          Choose a file and a peer to start. The key exchange, the QBER check, and chunk progress show up here
          as the two nodes report them.
        </p>
      </div>
    )
  }

  const outgoing = transfer.direction === 'outgoing'
  const note = waitingNote(transfer)

  return (
    <article aria-labelledby="transfer-title" className="space-y-8">
      <header className="space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 space-y-1">
            <h2 id="transfer-title" className="text-title font-semibold break-all">{transfer.filename}</h2>
            <p className="text-ink-2">
              {outgoing ? 'Sending to' : 'Receiving from'} <span className="text-ink">{transfer.peer.name}</span>{' '}
              <span className="font-mono text-small">({transfer.peer.host})</span>, {formatBytes(transfer.file_size)}
            </p>
          </div>
          <Actions key={transfer.id} transfer={transfer} onRespond={onRespond} onCancel={onCancel} busy={busy} />
        </div>
        <p aria-live="polite" className="font-medium">
          <StatusLabel status={transfer.status} direction={transfer.direction} />
        </p>
        {note ? <p className="text-ink-2">{note}</p> : null}
        {transfer.error && !['cancelled', 'rejected', 'aborted_qber'].includes(transfer.status) ? (
          <p className="text-small text-danger">{transfer.error}</p>
        ) : null}
        {transfer.output_path ? (
          <p className="text-small text-ink-2">
            Saved to <span className="font-mono break-all text-ink">{transfer.output_path}</span>
          </p>
        ) : null}
        {actionError ? <p role="alert" className="text-small text-danger">{actionError}</p> : null}
      </header>

      <ProtocolView transfer={transfer} />
      <LiveLog events={events} />
    </article>
  )
}
