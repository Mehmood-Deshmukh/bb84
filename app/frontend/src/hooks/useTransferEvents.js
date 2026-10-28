// @ts-check
import { useEffect, useState } from 'react'
import { subscribeToTransfer } from '../api/client'

/** @typedef {import('../api/types').TransferEvent} TransferEvent */

/**
 * All protocol events of one transfer, in order, kept live through the SSE stream.
 *
 * @param {string | null} transferId
 * @returns {TransferEvent[]}
 */
export function useTransferEvents(transferId) {
  const [state, setState] = useState(/** @type {{ id: string | null, events: TransferEvent[] }} */ ({ id: null, events: [] }))

  useEffect(() => {
    if (!transferId) return undefined
    return subscribeToTransfer(transferId, (event) => {
      setState((prev) => {
        if (prev.id !== transferId) return { id: transferId, events: [event] }
        const last = prev.events.at(-1)
        if (last && event.seq <= last.seq) return prev // replayed after a reconnect
        return { id: transferId, events: [...prev.events, event] }
      })
    })
  }, [transferId])

  return state.id === transferId ? state.events : []
}
