import { useState } from 'react'
import { API_BASE } from '../api/client'

function RenameForm({ initial, onSave, onClose }) {
  const [name, setName] = useState(initial)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setSaving(true)
    try {
      await onSave(name.trim())
      onClose()
    } catch (err) {
      setError(err.message)
      setSaving(false)
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
      <label htmlFor="node-name" className="sr-only">Node name</label>
      <input
        id="node-name"
        name="node-name"
        autoComplete="off"
        spellCheck={false}
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => e.key === 'Escape' && onClose()}
        maxLength={63}
        pattern="[^.]+"
        title="Up to 63 characters, no dots"
        required
        autoFocus
        className="w-56 rounded-sm border border-rule bg-surface px-2 py-1 text-body"
      />
      <button type="submit" disabled={saving} className="rounded-sm bg-accent px-3 py-1 text-small font-medium text-on-accent hover:bg-accent/85">
        {saving ? 'Saving…' : 'Save name'}
      </button>
      <button type="button" onClick={onClose} className="px-2 py-1 text-small text-ink-2 underline-offset-2 hover:underline">
        Cancel
      </button>
      {error ? <p role="alert" className="w-full text-small text-danger">{error}</p> : null}
    </form>
  )
}

export default function NodeHeader({ node, busy, error, onRename }) {
  const [renaming, setRenaming] = useState(false)

  return (
    <header className="border-b border-rule bg-surface">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
        {renaming && node ? (
          <RenameForm initial={node.name} onSave={onRename} onClose={() => setRenaming(false)} />
        ) : (
          <div className="flex items-baseline gap-3">
            <h1 className="text-section font-semibold">{node?.name ?? 'QKD node'}</h1>
            {node ? (
              <button
                type="button"
                onClick={() => setRenaming(true)}
                className="text-small text-ink-2 underline underline-offset-2 hover:text-ink"
              >
                Rename
              </button>
            ) : null}
          </div>
        )}
        {node ? (
          <dl className="flex flex-wrap gap-x-6 gap-y-1 text-small text-ink-2">
            <div className="flex gap-1.5">
              <dt>Address</dt>
              <dd translate="no" className="font-mono text-ink">{node.host}:{node.port}</dd>
            </div>
            <div className="flex gap-1.5">
              <dt>Status</dt>
              <dd className="text-ink">{busy ? 'Running a transfer' : 'Idle'}</dd>
            </div>
          </dl>
        ) : null}
        <p className="text-small text-ink-2 sm:ml-auto">BB84 key exchange, AES-256-GCM transfer</p>
      </div>
      {error ? (
        <p role="alert" className="border-t border-rule bg-paper px-4 py-2 text-small text-danger sm:px-6">
          Can’t reach the node at <span translate="no" className="font-mono">{API_BASE}</span>. Start it with{' '}
          <code translate="no" className="font-mono">qkd-node</code>, or set <code translate="no" className="font-mono">VITE_API_BASE_URL</code>.
        </p>
      ) : null}
    </header>
  )
}
