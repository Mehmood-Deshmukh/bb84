// @ts-check
// Types mirroring the backend's Pydantic models (src/qkd/services/api/models.py).
// See http://127.0.0.1:8000/docs for the live schema.

/**
 * @typedef {'pending'|'accepted'|'key_exchange'|'transferring'|'completed'|'rejected'|'aborted_qber'|'aborted_auth'|'failed'|'cancelled'} TransferStatus
 * @typedef {'outgoing'|'incoming'} Direction
 * @typedef {'connecting'|'authentication'|'quantum_transmission'|'sifting'|'qber_estimation'|'privacy_amplification'|'key_confirmation'|'file_transfer'|'done'} Stage
 * @typedef {'new'|'pinned'|'verified'} PeerTrust
 *
 * @typedef {object} PeerRef
 * @property {string} id
 * @property {string} name
 * @property {string} host
 * @property {number} port
 *
 * @typedef {object} TransferProgress
 * @property {number} chunks_done
 * @property {number} num_chunks
 * @property {number} bytes_done
 * @property {number} total_bytes
 *
 * @typedef {object} Transfer
 * @property {string} id
 * @property {Direction} direction
 * @property {TransferStatus} status
 * @property {Stage|null} stage
 * @property {string} filename
 * @property {number} file_size
 * @property {PeerRef} peer
 * @property {string} created_at
 * @property {string} updated_at
 * @property {number|null} raw_qubits
 * @property {number|null} sifted_length
 * @property {number|null} sample_size
 * @property {number|null} qber
 * @property {number|null} qber_threshold
 * @property {number|null} key_bits
 * @property {string|null} [auth_mode]
 * @property {string|null} [peer_fingerprint]
 * @property {PeerTrust|null} [peer_trust]
 * @property {number|null} [handshake_ms]
 * @property {number|null} [auth_overhead_bytes]
 * @property {TransferProgress|null} progress
 * @property {string|null} output_path
 * @property {string|null} error
 *
 * @typedef {object} Node
 * @property {string} id
 * @property {string} name
 * @property {string} host
 * @property {number} port
 * @property {'idle'|'busy'} status
 * @property {string} version
 * @property {string|null} [fingerprint]
 *
 * @typedef {object} Peer
 * @property {string} id
 * @property {string} name
 * @property {string} host
 * @property {number} port
 * @property {boolean} reachable
 * @property {string|null} [fingerprint]
 * @property {PeerTrust|null} [trust]
 *
 * @typedef {object} HistoryEntry
 * @property {string} id
 * @property {string} finished_at
 * @property {Direction} direction
 * @property {TransferStatus} status
 * @property {string} filename
 * @property {number} file_size
 * @property {string} peer_name
 * @property {string} peer_host
 * @property {number|null} qber
 * @property {number|null} key_bits
 * @property {string|null} [auth_mode]
 * @property {string|null} [peer_fingerprint]
 * @property {PeerTrust|null} [peer_trust]
 * @property {string|null} error
 *
 * @typedef {object} TransferEvent
 * @property {number} seq
 * @property {'log'|'stage'|'metrics'|'progress'|'listening'|'result'|'status'} type
 * @property {string} transfer_id
 * @property {Stage|null} stage
 * @property {Record<string, any>} payload
 * @property {number} ts
 */

/** @type {ReadonlySet<TransferStatus>} */
export const TERMINAL_STATUSES = new Set(['completed', 'rejected', 'aborted_qber', 'aborted_auth', 'failed', 'cancelled'])

/** @type {ReadonlySet<TransferStatus>} */
export const ACTIVE_STATUSES = new Set(['accepted', 'key_exchange', 'transferring'])

/** Protocol stages in order, as alice/bob report them. @type {ReadonlyArray<Stage>} */
export const STAGES = [
  'connecting',
  'authentication',
  'quantum_transmission',
  'sifting',
  'qber_estimation',
  'privacy_amplification',
  'key_confirmation',
  'file_transfer',
]
