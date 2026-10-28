import { useLayoutEffect, useRef } from 'react'

const LEVEL_MARK = { success: '✓', error: '✗', warning: '!', info: '·', raw: ' ' }
const LEVEL_CLASS = { error: 'text-danger', warning: 'text-danger', raw: 'text-ink-2' }

/** Monospace view of the log events alice/bob emit, kept scrolled to the end unless the reader scrolls up. */
export default function LiveLog({ events }) {
  const scroller = useRef(null)
  const pinned = useRef(true)
  const lines = events.filter((e) => e.type === 'log')

  useLayoutEffect(() => {
    const el = scroller.current
    if (el && pinned.current) el.scrollTop = el.scrollHeight
  }, [lines.length])

  const onScroll = () => {
    const el = scroller.current
    pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
  }

  return (
    <section aria-labelledby="log-heading" className="space-y-2">
      <h3 id="log-heading" className="font-medium">Protocol log</h3>
      <div
        ref={scroller}
        onScroll={onScroll}
        role="log"
        aria-labelledby="log-heading"
        tabIndex={0}
        className="h-72 overflow-y-auto border border-rule bg-well px-3 py-2 font-mono text-small [content-visibility:auto]"
      >
        {lines.length === 0 ? (
          <p className="text-ink-2">The log starts when the peer accepts.</p>
        ) : (
          lines.map((e) =>
            e.payload.level === 'section' ? (
              <p key={e.seq} className="mt-3 mb-1 font-medium first:mt-0">{e.payload.message}</p>
            ) : (
              <p key={e.seq} className={`grid grid-cols-[1.25rem_minmax(0,1fr)] break-words ${LEVEL_CLASS[e.payload.level] ?? ''}`}>
                <span aria-hidden="true">{LEVEL_MARK[e.payload.level] ?? '·'}</span>
                <span>{e.payload.message}</span>
              </p>
            ),
          )
        )}
      </div>
    </section>
  )
}
