import { useEffect, useRef } from 'react'
import { formatBytes } from '../lib/format'

/**
 * Modal for a new incoming offer. Escape or "Decide later" closes it; the offer stays
 * pending in the transfer list, where it can still be accepted or declined.
 */
export default function IncomingDialog({ transfer, onRespond, onDismiss, busy }) {
  const ref = useRef(null)

  useEffect(() => {
    const dialog = ref.current
    if (dialog && !dialog.open) dialog.showModal()
    return () => dialog?.close()
  }, [])

  return (
    <dialog
      ref={ref}
      aria-labelledby="incoming-title"
      aria-describedby="incoming-details"
      onCancel={(e) => {
        e.preventDefault()
        onDismiss(transfer.id)
      }}
      className="m-auto w-[min(32rem,calc(100vw-2rem))] rounded-sm border border-rule bg-surface p-0 text-ink"
    >
      <div className="space-y-5 p-6">
        <h2 id="incoming-title" className="text-section font-semibold">
          {transfer.peer.name} wants to send you a file
        </h2>
        <dl id="incoming-details" className="grid grid-cols-[6rem_minmax(0,1fr)] gap-y-1.5 text-small">
          <dt className="text-ink-2">File</dt>
          <dd className="font-medium break-all">{transfer.filename}</dd>
          <dt className="text-ink-2">Size</dt>
          <dd>{formatBytes(transfer.file_size)}</dd>
          <dt className="text-ink-2">From</dt>
          <dd className="font-mono">{transfer.peer.host}:{transfer.peer.port}</dd>
        </dl>
        <p className="text-small text-ink-2">
          Accepting starts a BB84 key exchange. If the error rate is too high, both sides stop before any file
          data is sent.
        </p>
        <div className="flex flex-wrap gap-2">
          <button type="button" autoFocus disabled={busy} onClick={() => onRespond(transfer.id, 'accepted')}
            className="rounded-sm bg-accent px-4 py-2 font-medium text-on-accent hover:bg-accent/85">
            Accept and receive
          </button>
          <button type="button" disabled={busy} onClick={() => onRespond(transfer.id, 'rejected')}
            className="rounded-sm border border-rule px-4 py-2 font-medium hover:border-ink-2">
            Decline
          </button>
          <button type="button" onClick={() => onDismiss(transfer.id)}
            className="px-2 py-2 text-small text-ink-2 underline underline-offset-2 hover:text-ink sm:ml-auto">
            Decide later
          </button>
        </div>
      </div>
    </dialog>
  )
}
