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
  const text = status === 'pending' && direction === 'incoming' ? 'Waiting for your answer' : STATUS_LABEL[status]
  const tone = status === 'aborted_qber' || status === 'failed' ? 'text-danger' : ''
  return (
    <span className={`inline-flex items-center gap-1.5 ${tone} ${className}`}>
      <StatusGlyph status={status} />
      {text}
    </span>
  )
}
