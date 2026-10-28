import { formatBytes, formatPercent, formatTime } from '../lib/format'
import StatusLabel from './StatusLabel'

/** Finished transfers from the node's history file. Stacks into labelled rows on small screens. */
export default function HistoryTable({ entries }) {
  return (
    <section aria-labelledby="history-heading" className="space-y-3">
      <h2 id="history-heading" className="text-section font-semibold">History</h2>
      {entries.length === 0 ? (
        <p className="text-small text-ink-2">Finished transfers are kept here, including declined and aborted ones.</p>
      ) : (
        <table className="w-full border-collapse text-small">
          <thead className="sr-only sm:not-sr-only">
            <tr className="border-b border-rule text-left text-ink-2">
              <th scope="col" className="py-2 pr-4 font-medium">Finished</th>
              <th scope="col" className="py-2 pr-4 font-medium">File</th>
              <th scope="col" className="py-2 pr-4 font-medium">Peer</th>
              <th scope="col" className="py-2 pr-4 text-right font-medium">QBER</th>
              <th scope="col" className="py-2 font-medium">Result</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id} className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-3 border-b border-rule py-2 sm:table-row sm:py-0">
                <td className="text-ink-2 sm:py-2 sm:pr-4 sm:align-top">{formatTime(e.finished_at)}</td>
                <td className="min-w-0 sm:py-2 sm:pr-4 sm:align-top">
                  <span className="block truncate font-medium">{e.filename}</span>
                  <span className="text-ink-2">{formatBytes(e.file_size)}</span>
                </td>
                <td className="col-start-2 sm:py-2 sm:pr-4 sm:align-top">
                  {e.direction === 'outgoing' ? 'To ' : 'From '}
                  {e.peer_name}
                </td>
                <td className="col-start-2 font-mono sm:py-2 sm:pr-4 sm:text-right sm:align-top">
                  <span className="sm:sr-only">QBER </span>
                  {e.qber == null ? '–' : formatPercent(e.qber)}
                </td>
                <td className="col-start-2 sm:py-2 sm:align-top">
                  <StatusLabel status={e.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
