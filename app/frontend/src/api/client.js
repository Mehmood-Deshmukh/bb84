// @ts-check
// The only module that talks to the backend node. Components use these functions
// (through the hooks in src/hooks), never fetch() directly.

import { TERMINAL_STATUSES } from './types'

/** @typedef {import('./types').Transfer} Transfer */
/** @typedef {import('./types').TransferStatus} TransferStatus */
/** @typedef {import('./types').Direction} Direction */
/** @typedef {import('./types').Node} Node */
/** @typedef {import('./types').Peer} Peer */
/** @typedef {import('./types').HistoryEntry} HistoryEntry */
/** @typedef {import('./types').TransferEvent} TransferEvent */

export const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
const V1 = `${API_BASE}/api/v1`

/** Error thrown for any non-2xx response. Carries the backend's {error: {code, message}} body. */
export class ApiError extends Error {
  /**
   * @param {number} status
   * @param {string} code
   * @param {string} message
   */
  constructor(status, code, message) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

/**
 * @template T
 * @param {string} path
 * @param {RequestInit & { json?: unknown }} [options]
 * @returns {Promise<T>}
 */
async function request(path, options = {}) {
  const { json, headers, ...rest } = options
  const init = json === undefined ? rest : {
    ...rest,
    body: JSON.stringify(json),
    headers: { 'Content-Type': 'application/json', ...headers },
  }
  let response
  try {
    response = await fetch(`${V1}${path}`, init)
  } catch {
    throw new ApiError(0, 'network_error', `Cannot reach the node at ${API_BASE}`)
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const error = body?.error
    throw new ApiError(response.status, error?.code ?? 'http_error', error?.message ?? response.statusText)
  }
  return body
}

/** @returns {Promise<Node>} */
export const getNode = () => request('/node')

/** @param {string} name @returns {Promise<Node>} */
export const renameNode = (name) => request('/node', { method: 'PATCH', json: { name } })

/** @returns {Promise<Peer[]>} */
export const listPeers = async () => (await request('/peers')).items

/** @param {string} id @returns {Promise<Peer>} */
export const getPeer = (id) => request(`/peers/${encodeURIComponent(id)}`)

/**
 * Mark a peer's identity as verified.
 * @param {string} id
 * @returns {Promise<Peer>}
 */
export const verifyPeer = (id) =>
  request(`/peers/${encodeURIComponent(id)}/trust`, { method: 'PUT' })
export const verifyPeerTrust = verifyPeer

/**
 * Forget a peer's identity (resetting trust to 'new').
 * @param {string} id
 * @returns {Promise<Peer>}
 */
export const forgetPeer = (id) =>
  request(`/peers/${encodeURIComponent(id)}/trust`, { method: 'DELETE' })
export const forgetPeerTrust = forgetPeer

/**
 * @param {{ direction?: Direction, status?: TransferStatus[] }} [filter]
 * @returns {Promise<Transfer[]>}
 */
export async function listTransfers(filter = {}) {
  const params = new URLSearchParams()
  if (filter.direction) params.set('direction', filter.direction)
  for (const status of filter.status ?? []) params.append('status', status)
  const query = params.size ? `?${params}` : ''
  return (await request(`/transfers${query}`)).items
}

/** @param {string} id @returns {Promise<Transfer>} */
export const getTransfer = (id) => request(`/transfers/${encodeURIComponent(id)}`)

/**
 * Upload a file and offer it to a peer. Resolves with the new pending transfer.
 * @param {File} file
 * @param {string} peerId
 * @returns {Promise<Transfer>}
 */
export function createTransfer(file, peerId) {
  const form = new FormData()
  form.append('file', file)
  form.append('peer_id', peerId)
  return request('/transfers', { method: 'POST', body: form })
}

/**
 * Accept or reject an incoming transfer.
 * @param {string} id
 * @param {'accepted'|'rejected'} status
 * @returns {Promise<Transfer>}
 */
export const respondToTransfer = (id, status) =>
  request(`/transfers/${encodeURIComponent(id)}`, { method: 'PATCH', json: { status } })

/** @param {string} id @returns {Promise<Transfer>} */
export const cancelTransfer = (id) => request(`/transfers/${encodeURIComponent(id)}`, { method: 'DELETE' })

/** @returns {Promise<HistoryEntry[]>} */
export const getHistory = async () => (await request('/history')).items

/**
 * Stream a transfer's protocol events (server-sent events). The stream replays past
 * events first and closes itself once the transfer reaches a terminal status.
 *
 * @param {string} id
 * @param {(event: TransferEvent) => void} onEvent
 * @param {{ onError?: () => void }} [options]
 * @returns {() => void} unsubscribe
 */
export function subscribeToTransfer(id, onEvent, options = {}) {
  const source = new EventSource(`${V1}/transfers/${encodeURIComponent(id)}/events`)
  source.onmessage = (message) => {
    /** @type {TransferEvent} */
    const event = JSON.parse(message.data)
    onEvent(event)
    if (event.type === 'status' && TERMINAL_STATUSES.has(event.payload.status)) source.close()
  }
  source.onerror = () => {
    // EventSource reconnects by itself (resuming via Last-Event-ID) unless the server is gone.
    if (source.readyState === EventSource.CLOSED) options.onError?.()
  }
  return () => source.close()
}
