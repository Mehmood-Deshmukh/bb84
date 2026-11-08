import { useState } from 'react'
import { TERMINAL_STATUSES } from '../api/types'
import { RESTART_REASON, STAGE_LABEL, formatBytes } from '../lib/format'
import LiveLog from './LiveLog'
import ProtocolView from './ProtocolView'
import StatusLabel from './StatusLabel'

function Actions({ transfer, onRespond, onResume, onCancel, busy }) {
  if (transfer.status === 'interrupted') {
    return (
      <div className="flex flex-wrap gap-2">
        {transfer.direction === 'outgoing' ? (
          <button type="button" disabled={busy} onClick={() => onResume(transfer.id)}
            className="rounded-sm bg-accent px-4 py-2 font-medium text-on-accent hover:bg-accent/85">
            Resume transfer
          </button>
        ) : null}
        <CancelButton transfer={transfer} onCancel={onCancel} busy={busy} label="Discard transfer" />
      </div>
    )
  }
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
function CancelButton({ transfer, onCancel, busy, label = 'Cancel transfer' }) {
  const [confirming, setConfirming] = useState(false)
  if (!confirming) {
    return (
      <button type="button" disabled={busy} onClick={() => setConfirming(true)}
        className="rounded-sm border border-rule px-4 py-2 font-medium hover:border-danger hover:text-danger">
        {label}
      </button>
    )
  }
  return (
    <div role="group" aria-label="Confirm cancellation" className="flex flex-wrap items-center gap-2">
      <span className="text-small">
        {transfer.status === 'interrupted'
          ? 'Discard this transfer and the data already received, on both nodes?'
          : 'Stop this transfer on both nodes?'}
      </span>
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
  if (transfer.status === 'interrupted') {
    const done = transfer.progress ? ` after ${formatBytes(transfer.progress.bytes_done)} of ${formatBytes(transfer.progress.total_bytes)}` : ''
    return transfer.direction === 'outgoing'
      ? `The connection stopped${done}. Resuming runs a new key exchange and sends only what ${transfer.peer.name} has not yet verified.`
      : `The connection stopped${done}. The data already verified is kept; ${transfer.peer.name} can resume the transfer.`
  }
  if (transfer.status !== 'pending') return null
  if ((transfer.attempt ?? 1) > 1) {
    return transfer.direction === 'outgoing'
      ? `Waiting for ${transfer.peer.name} to accept the resume. Nothing has been sent yet in this attempt.`
      : `${transfer.peer.name} wants to resume sending this file. Nothing is received until you accept.`
  }
  return transfer.direction === 'outgoing'
    ? `Waiting for ${transfer.peer.name} to accept. Nothing has been sent yet.`
    : `${transfer.peer.name} wants to send you this file. Nothing is received until you accept.`
}

/** What a resumed attempt did differently: continued after verified data, or had to start over. */
function resumeNote(transfer) {
  if (transfer.resume_restart_reason) {
    const why = RESTART_REASON[transfer.resume_restart_reason] ?? transfer.resume_restart_reason
    return `Sent again from the start: ${why}.`
  }
  if (transfer.resumed_from_bytes > 0) {
    return `Resumed: the first ${formatBytes(transfer.resumed_from_bytes)} were already verified and were not sent again (attempt ${transfer.attempt ?? 2}).`
  }
  return null
}

/** Prominent result panel displayed when a transfer aborts due to authentication / impersonation failure. */
function ImpersonationAlert({ transfer }) {
  const stageName = transfer.stage ? (STAGE_LABEL[transfer.stage] || transfer.stage) : 'Authentication'

  return (
    <section role="alert" aria-labelledby="impersonation-heading" className="rounded-sm border-2 border-danger bg-danger/10 p-4 space-y-3">
      <div className="flex items-center gap-2 text-danger font-semibold text-section">
        <svg width="22" height="22" viewBox="0 0 20 20" fill="none" className="shrink-0" aria-hidden="true">
          <path d="M10 2 17 5.5v5.5c0 4.2-3 7-7 8.5C6 18 3 15.2 3 11V5.5L10 2z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
          <path d="M10 6.5v4.5M10 14h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
        <h3 id="impersonation-heading">Impersonation Detected — Transfer Aborted</h3>
      </div>

      <p className="text-small text-ink">
        Cryptographic authentication failed during the <strong>{stageName}</strong> stage.
        An untrusted peer or active adversary attempted to compromise the classical channel.
        No quantum key was established and no file data was transferred.
      </p>

      {transfer.error ? (
        <div className="rounded-sm border border-danger/30 bg-surface px-3 py-2 text-small">
          <span className="font-medium text-danger">Failure Reason: </span>
          <span className="font-mono text-ink select-all">{transfer.error}</span>
        </div>
      ) : null}

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 border-t border-danger/20 pt-2.5 text-fine text-ink-2 sm:grid-cols-4">
        <div>
          <dt className="font-medium text-ink-2">Failed Stage</dt>
          <dd className="font-mono text-ink">{transfer.stage ?? 'authentication'}</dd>
        </div>
        {transfer.auth_mode ? (
          <div>
            <dt className="font-medium text-ink-2">Auth Mode</dt>
            <dd className="font-mono text-ink uppercase">{transfer.auth_mode}</dd>
          </div>
        ) : null}
        {transfer.peer_trust ? (
          <div>
            <dt className="font-medium text-ink-2">Peer Trust</dt>
            <dd className="font-mono text-ink capitalize">{transfer.peer_trust}</dd>
          </div>
        ) : null}
        {transfer.peer_fingerprint ? (
          <div className="col-span-2 sm:col-span-1">
            <dt className="font-medium text-ink-2">Peer Fingerprint</dt>
            <dd className="font-mono text-ink truncate select-all" title={transfer.peer_fingerprint}>
              {transfer.peer_fingerprint}
            </dd>
          </div>
        ) : null}
      </dl>
    </section>
  )
}

export default function TransferPanel({ transfer, events, onRespond, onResume, onCancel, busy, actionError }) {
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
  const resumed = resumeNote(transfer)

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
          <Actions key={transfer.id} transfer={transfer} onRespond={onRespond} onResume={onResume} onCancel={onCancel} busy={busy} />
        </div>
        <p aria-live="polite" className="font-medium">
          <StatusLabel status={transfer.status} direction={transfer.direction} />
        </p>
        {note ? <p className="text-ink-2">{note}</p> : null}
        {resumed ? <p className="text-small text-ink-2">{resumed}</p> : null}
        {transfer.status === 'aborted_auth' ? (
          <ImpersonationAlert transfer={transfer} />
        ) : null}
        {transfer.error && !['cancelled', 'rejected', 'aborted_qber', 'aborted_auth', 'interrupted'].includes(transfer.status) ? (
          <p className="text-small text-danger">{transfer.error}</p>
        ) : null}
        {transfer.status === 'interrupted' && transfer.error ? (
          <p className="text-small text-ink-2">Reason: <span className="font-mono break-all">{transfer.error}</span></p>
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
