/** Radio list of discovered peers. Unreachable peers are listed but cannot be chosen. */
export default function PeerList({ peers, selectedId, onSelect, loading }) {
  if (!peers.length) {
    return (
      <p className="text-small text-ink-2">
        {loading
          ? 'Looking for peers on this network…'
          : 'No peers found yet. Start qkd-node on another machine on the same network and it appears here within a few seconds.'}
      </p>
    )
  }

  return (
    <ul className="divide-y divide-rule border-y border-rule">
      {peers.map((peer) => (
        <li key={peer.id}>
          <label
            className={`flex items-start gap-3 px-1 py-2.5 ${peer.reachable ? 'cursor-pointer hover:bg-surface' : 'cursor-not-allowed text-ink-2'}`}
          >
            <input
              type="radio"
              name="peer"
              value={peer.id}
              checked={selectedId === peer.id}
              onChange={() => onSelect(peer.id)}
              disabled={!peer.reachable}
              className="mt-1 size-4 accent-(--color-accent)"
            />
            <span className="min-w-0">
              <span className="block truncate font-medium">{peer.name}</span>
              <span translate="no" className="block font-mono text-small text-ink-2">
                {peer.host}:{peer.port}
                {peer.reachable ? '' : ', not responding'}
              </span>
            </span>
          </label>
        </li>
      ))}
    </ul>
  )
}
