// @ts-check
import { getHistory, getNode, listPeers, listTransfers } from '../api/client'
import { usePolling } from './usePolling'

/** Polling intervals (ms). Transfers poll fastest so incoming offers show up quickly. */
const INTERVALS = { node: 5000, peers: 3000, transfers: 1500, history: 5000 }

export const useNode = () => usePolling(getNode, INTERVALS.node)
export const usePeers = () => usePolling(listPeers, INTERVALS.peers)
export const useTransfers = () => usePolling(listTransfers, INTERVALS.transfers)
export const useHistory = () => usePolling(getHistory, INTERVALS.history)
