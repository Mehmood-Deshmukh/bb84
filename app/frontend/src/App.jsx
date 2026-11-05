import { useState } from 'react'
import { cancelTransfer, createTransfer, renameNode, respondToTransfer, resumeTransfer } from './api/client'
import { ACTIVE_STATUSES } from './api/types'
import HistoryTable from './components/HistoryTable'
import IncomingDialog from './components/IncomingDialog'
import NodeHeader from './components/NodeHeader'
import SendForm from './components/SendForm'
import TransferList from './components/TransferList'
import TransferPanel from './components/TransferPanel'
import { useHistory, useNode, usePeers, useTransfers } from './hooks/useNodeState'
import { useTransferEvents } from './hooks/useTransferEvents'

const NONE = []

/** Explicit choice first, then whatever is running, then the newest transfer. */
function pickTransfer(transfers, selectedId) {
  return transfers.find((t) => t.id === selectedId)
    ?? transfers.find((t) => ACTIVE_STATUSES.has(t.status))
    ?? transfers[0]
    ?? null
}

export default function App() {
  const node = useNode()
  const peers = usePeers()
  const transfers = useTransfers()
  const history = useHistory()

  // The selected transfer lives in the URL hash, so a reload or a shared link reopens it.
  const [selectedId, setSelected] = useState(() => window.location.hash.slice(1) || null)
  const setSelectedId = (id) => {
    setSelected(id)
    window.history.replaceState(null, '', id ? `#${id}` : window.location.pathname)
  }
  const [dismissed, setDismissed] = useState(() => new Set())
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState(null)

  const transferList = transfers.data ?? NONE
  const selected = pickTransfer(transferList, selectedId)
  const events = useTransferEvents(selected?.id ?? null)
  const running = transferList.some((t) => ACTIVE_STATUSES.has(t.status))
  const offer = transferList.find((t) => t.direction === 'incoming' && t.status === 'pending' && !dismissed.has(t.id))

  const runAction = async (id, action) => {
    setBusy(true)
    setActionError(null)
    try {
      await action()
      setSelectedId(id)
    } catch (err) {
      setActionError(err.message)
    } finally {
      setBusy(false)
      transfers.refresh()
    }
  }

  const send = async (file, peerId) => {
    const created = await createTransfer(file, peerId)
    setSelectedId(created.id)
    transfers.refresh()
  }

  const respond = (id, status) => {
    setDismissed((prev) => new Set(prev).add(id))
    return runAction(id, () => respondToTransfer(id, status))
  }

  const cancel = (id) => runAction(id, () => cancelTransfer(id))

  const resume = (id) => runAction(id, () => resumeTransfer(id))

  const dismiss = (id) => {
    setDismissed((prev) => new Set(prev).add(id))
    setSelectedId(id)
  }

  const rename = async (name) => {
    await renameNode(name)
    node.refresh()
  }

  return (
    <div className="flex min-h-dvh flex-col">
      <a href="#transfer" className="sr-only z-10 bg-accent px-3 py-2 text-on-accent focus:not-sr-only focus:absolute focus:top-2 focus:left-2">
        Skip to transfer
      </a>
      <NodeHeader node={node.data} busy={running} error={node.error} onRename={rename} />

      <main className="mx-auto grid w-full max-w-7xl flex-1 lg:grid-cols-[20rem_minmax(0,1fr)] lg:grid-rows-[auto_1fr]">
        <div className="border-b border-rule px-4 py-6 sm:px-6 lg:border-r lg:border-b-0">
          <SendForm peers={peers.data ?? NONE} peersLoading={peers.data === undefined} onSend={send} />
        </div>
        <div id="transfer" tabIndex={-1} className="min-w-0 border-b border-rule px-4 py-6 outline-none sm:px-6 lg:col-start-2 lg:row-span-2 lg:row-start-1 lg:border-b-0">
          <TransferPanel
            transfer={selected}
            events={events}
            onRespond={respond}
            onResume={resume}
            onCancel={cancel}
            busy={busy}
            actionError={actionError}
          />
        </div>
        <div className="border-b border-rule px-4 py-6 sm:px-6 lg:row-start-2 lg:border-r lg:border-b-0">
          <TransferList transfers={transferList} selectedId={selected?.id} onSelect={setSelectedId} onResume={resume} busy={busy} />
        </div>
      </main>

      <footer className="border-t border-rule">
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
          <HistoryTable entries={history.data ?? NONE} />
        </div>
      </footer>

      {offer ? <IncomingDialog key={offer.id} transfer={offer} onRespond={respond} onDismiss={dismiss} busy={busy} /> : null}
    </div>
  )
}
