import { ACTIVE_STATUSES } from '../api/types'
import { STATUS_LABEL } from '../lib/format'

/** Shape plus text, so status never depends on colour alone. */
function StatusGlyph({ status }) {
  const common = { width: 10, height: 10, viewBox: '0 0 10 10', 'aria-hidden': true, className: 'shrink-0' }
  if (status === 'completed') {
    return (
      <svg {...common}>
        <path d="M1.5 5.2 4 7.6 8.6 2.4" fill="none" stroke="currentColor" strokeWidth="1.6" />
      </svg>
    )
  }
  if (status === 'aborted_auth') {
    return (
      <svg {...common} className="shrink-0 text-danger" title="Authentication / Impersonation failure">
        <path d="M5 1 8.8 2.6v2.8c0 2-1.4 3.3-3.8 4.1C2.4 8.7 1 7.4 1 5.4V2.6L5 1z" fill="none" stroke="currentColor" strokeWidth="1.2" />
        <path d="M5 3.2v2.2M5 6.8h.01" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    )
  }
  if (status === 'aborted_qber' || status === 'failed') {
    return (
      <svg {...common} className="shrink-0 text-danger">
        <path d="M2 2l6 6M8 2 2 8" stroke="currentColor" strokeWidth="1.6" />
      </svg>
    )
  }
  if (status === 'rejected' || status === 'cancelled') {
    return (
      <svg {...common} className="shrink-0 text-ink-2">
        <path d="M2 5h6" stroke="currentColor" strokeWidth="1.6" />
      </svg>
    )
  }
  if (ACTIVE_STATUSES.has(status)) {
    return (
      <svg {...common} className="shrink-0 text-accent">
        <circle cx="5" cy="5" r="4" fill="currentColor" />
      </svg>
    )
  }
  return (
    <svg {...common} className="shrink-0 text-ink-2">
      <circle cx="5" cy="5" r="3.4" fill="none" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  )
}

export default function StatusLabel({ status, direction, className = '' }) {
  const text = status === 'pending' && direction === 'incoming' ? 'Waiting for your answer' : (STATUS_LABEL[status] || status)

  if (status === 'aborted_auth') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-sm border border-danger/40 bg-danger/10 px-1.5 py-0.5 text-danger font-medium ${className}`}>
        <StatusGlyph status={status} />
        <span>{text}</span>
      </span>
    )
  }

  const tone = status === 'aborted_qber' || status === 'failed' ? 'text-danger' : ''
  return (
    <span className={`inline-flex items-center gap-1.5 ${tone} ${className}`}>
      <StatusGlyph status={status} />
      <span>{text}</span>
    </span>
  )
}
