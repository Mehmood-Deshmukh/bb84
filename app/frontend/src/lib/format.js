// @ts-check
/** @typedef {import('../api/types').TransferStatus} TransferStatus */
/** @typedef {import('../api/types').Stage} Stage */

const integer = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 })
const oneDecimal = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1, minimumFractionDigits: 1 })

/** @param {number} bytes */
export function formatBytes(bytes) {
  if (bytes < 1024) return `${integer.format(bytes)}\u00a0B`
  const units = ['KB', 'MB', 'GB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${(value < 10 ? oneDecimal : integer).format(value)}\u00a0${units[unit]}`
}

/**
 * @param {number} fraction 0..1
 * @param {number} [digits]
 */
export const formatPercent = (fraction, digits = 1) =>
  new Intl.NumberFormat(undefined, { style: 'percent', minimumFractionDigits: digits, maximumFractionDigits: digits }).format(fraction)

/** @param {string} iso */
export function formatTime(iso) {
  const date = new Date(iso)
  const today = new Date().toDateString() === date.toDateString()
  return today
    ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/** @type {Record<TransferStatus, string>} */
export const STATUS_LABEL = {
  pending: 'Waiting for answer',
  accepted: 'Starting',
  key_exchange: 'Exchanging key',
  transferring: 'Sending file',
  completed: 'Completed',
  rejected: 'Declined',
  aborted_qber: 'Aborted: QBER too high',
  aborted_auth: 'Aborted: Impersonation detected',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

/** @type {Record<Stage, string>} */
export const STAGE_LABEL = {
  connecting: 'Connect',
  authentication: 'Authenticate',
  quantum_transmission: 'Send qubits',
  sifting: 'Sift bases',
  qber_estimation: 'Estimate QBER',
  reconciliation: 'Correct errors',
  privacy_amplification: 'Amplify privacy',
  key_confirmation: 'Confirm key',
  file_transfer: 'Stream file',
  done: 'Done',
}
