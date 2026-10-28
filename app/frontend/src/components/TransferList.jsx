import StatusLabel from './StatusLabel'

/** Transfers known to this node since it started. Selecting one shows it in the transfer panel. */
export default function TransferList({ transfers, selectedId, onSelect }) {
  return (
    <section aria-labelledby="transfers-heading" className="space-y-3">
      <h2 id="transfers-heading" className="text-section font-semibold">Transfers</h2>
      {transfers.length === 0 ? (
        <p className="text-small text-ink-2">Files you send or receive while this node runs are listed here.</p>
      ) : (
        <ul className="divide-y divide-rule border-y border-rule">
          {transfers.map((t) => {
            const selected = t.id === selectedId
            return (
              <li key={t.id}>
                <button
                  type="button"
                  onClick={() => onSelect(t.id)}
                  aria-current={selected ? 'true' : undefined}
                  className={`block w-full border-l-2 py-2.5 pr-2 pl-3 text-left ${
                    selected ? 'border-accent bg-surface' : 'border-transparent hover:bg-surface'
                  }`}
                >
                  <span className="block truncate font-medium">{t.filename}</span>
                  <span className="block text-small text-ink-2">
                    {t.direction === 'outgoing' ? `To ${t.peer.name}` : `From ${t.peer.name}`}
                  </span>
                  <StatusLabel status={t.status} direction={t.direction} className="text-small" />
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
