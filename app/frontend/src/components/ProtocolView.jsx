import { STAGES, TERMINAL_STATUSES } from '../api/types'
import { STAGE_LABEL, formatBytes, formatPercent } from '../lib/format'

const QBER_SCALE_MAX = 0.5
const QBER_TICKS = [0, 0.1, 0.2, 0.3, 0.4, 0.5]

/** done | current | failed | stopped | upcoming | skipped for each protocol stage. */
function stageStates(transfer) {
  const reached = transfer.stage ? STAGES.indexOf(transfer.stage) : -1
  const finished = TERMINAL_STATUSES.has(transfer.status)
  const paused = transfer.status === 'interrupted'
  const broke = transfer.status === 'aborted_qber' || transfer.status === 'aborted_auth' || transfer.status === 'failed'
  return STAGES.map((_, i) => {
    if (transfer.status === 'completed' || i < reached) return 'done'
    if (i === reached) return paused ? 'stopped' : finished ? (broke ? 'failed' : 'stopped') : 'current'
    return finished ? 'skipped' : 'upcoming'
  })
}

const STAGE_BAR = {
  done: 'bg-ink',
  current: 'bg-accent',
  failed: 'bg-danger',
  stopped: 'bg-ink-2',
  upcoming: 'bg-rule',
  skipped: 'bg-rule',
}

const STAGE_STATE_TEXT = {
  done: 'done',
  current: 'in progress',
  failed: 'failed here',
  stopped: 'stopped here',
  upcoming: 'not started',
  skipped: 'skipped',
}

function StageSequence({ transfer }) {
  const states = stageStates(transfer)
  return (
    <ol className="grid grid-cols-2 gap-x-3 gap-y-3 sm:grid-cols-4 xl:grid-cols-8">
      {STAGES.map((stage, i) => (
        <li key={stage} aria-current={states[i] === 'current' ? 'step' : undefined}>
          <div className={`mb-1.5 h-[3px] ${STAGE_BAR[states[i]]}`} />
          <span className={`text-small ${states[i] === 'upcoming' || states[i] === 'skipped' ? 'text-ink-2' : ''} ${states[i] === 'failed' ? 'text-danger' : ''}`}>
            <span className="font-mono">{i + 1}</span> {STAGE_LABEL[stage] || stage}
            <span className="sr-only"> ({STAGE_STATE_TEXT[states[i]]})</span>
          </span>
        </li>
      ))}
    </ol>
  )
}

function FunnelRow({ label, value, of, note, barClass }) {
  const width = value != null && of ? `${Math.max((value / of) * 100, value > 0 ? 1 : 0)}%` : '0%'
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_4.5rem] items-baseline gap-x-4 gap-y-1 sm:grid-cols-[11rem_4.5rem_minmax(0,1fr)]">
      <dt className="text-small">{label}</dt>
      <dd className="text-right font-mono">{value ?? '–'}</dd>
      <dd className="col-span-2 sm:col-span-1">
        <div className="h-2 bg-well" aria-hidden="true">
          <div className={`h-full transition-[width] duration-300 ${barClass}`} style={{ width }} />
        </div>
        {note ? <p className="mt-1 text-fine text-ink-2">{note}</p> : null}
      </dd>
    </div>
  )
}

/** Raw qubits -> sifted -> sample revealed -> bits hashed into the key. Bars are to scale. */
function KeyFunnel({ transfer }) {
  const { raw_qubits: raw, sifted_length: sifted, sample_size: sample, key_bits: keyBits } = transfer
  const kept = sifted != null && sample != null ? sifted - sample : null
  const abortedQber = transfer.status === 'aborted_qber'
  const abortedAuth = transfer.status === 'aborted_auth'
  const aborted = abortedQber || abortedAuth

  let note = null
  if (abortedAuth) {
    note = 'No key was derived: classical channel authentication failed'
  } else if (abortedQber) {
    note = 'No key was derived: the exchange stopped at the QBER check'
  } else if (keyBits) {
    note = `SHA-256 with a random salt gives the ${keyBits}-bit AES key (via HKDF)`
  }

  return (
    <section aria-labelledby="funnel-heading" className="space-y-3">
      <h3 id="funnel-heading" className="font-medium">Key material</h3>
      <dl className="space-y-3">
        <FunnelRow label="Qubits sent" value={raw} of={raw} barClass="bg-ink-2" />
        <FunnelRow
          label="Bases matched"
          value={sifted}
          of={raw}
          barClass="bg-ink-2"
          note={sifted != null && raw ? `${formatPercent(sifted / raw, 0)} of qubits; about half is expected` : null}
        />
        <FunnelRow
          label="Revealed for QBER"
          value={sample}
          of={raw}
          barClass="bg-[repeating-linear-gradient(135deg,var(--color-ink-2)_0_2px,transparent_2px_5px)]"
          note={sample != null ? 'Compared in the open, then discarded' : null}
        />
        <FunnelRow
          label={aborted ? 'Left over, discarded' : 'Hashed into the key'}
          value={kept}
          of={raw}
          barClass={aborted ? 'bg-ink-2' : 'bg-accent'}
          note={note}
        />
      </dl>
      {kept != null && keyBits && kept < keyBits ? (
        <p className="max-w-prose text-small text-ink-2">
          The {keyBits}-bit key comes from {kept} secret bits, so it holds at most {kept} bits of entropy.
          Raise <code className="font-mono">QKD_NUM_QUBITS</code> for more.
        </p>
      ) : null}
    </section>
  )
}

/** Measured QBER on a 0–50% scale with the abort threshold drawn as a hard line. */
function QberScale({ transfer }) {
  const { qber, qber_threshold: threshold, sample_size: sample } = transfer
  const measured = qber != null && threshold != null
  const pos = (v) => `${(Math.min(v, QBER_SCALE_MAX) / QBER_SCALE_MAX) * 100}%`
  const above = measured && qber >= threshold
  const differing = measured && sample ? Math.round(qber * sample) : null

  const summary = !measured
    ? transfer.status === 'aborted_auth'
      ? 'Authentication failed before quantum transmission took place.'
      : 'Measured after sifting, on a sample of the matching bits.'
    : `${differing} of ${sample} revealed bits differ. ${
      above
        ? `That is at or above the ${formatPercent(threshold, 0)} threshold, so both sides aborted and no file was sent.`
        : `That is below the ${formatPercent(threshold, 0)} threshold, so the key was kept.`
    }`

  return (
    <section aria-labelledby="qber-heading" className="space-y-3">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h3 id="qber-heading" className="font-medium">Quantum bit error rate</h3>
        <p className={`font-mono text-title ${above ? 'text-danger' : ''}`}>
          {measured ? formatPercent(qber) : '–'}
        </p>
      </div>

      <div
        role="img"
        aria-label={measured ? `QBER ${formatPercent(qber)}, threshold ${formatPercent(threshold, 0)}` : 'QBER not measured yet'}
        className="relative h-10"
      >
        <div className="absolute inset-x-0 top-4 h-2 bg-well" />
        {threshold != null ? (
          <>
            <div className="absolute top-4 right-0 h-2 bg-danger/15" style={{ left: pos(threshold) }} />
            <div className="absolute top-1 bottom-1 w-0.5 bg-danger" style={{ left: pos(threshold) }} />
            <span className="absolute -top-0.5 ml-1.5 text-fine text-danger" style={{ left: pos(threshold) }}>
              abort at {formatPercent(threshold, 0)}
            </span>
          </>
        ) : null}
        {measured ? (
          <div
            className={`absolute top-2.5 h-5 w-1.5 -translate-x-1/2 ${above ? 'bg-danger' : 'bg-accent'}`}
            style={{ left: pos(qber) }}
          />
        ) : null}
      </div>
      <div className="relative h-4 text-fine text-ink-2" aria-hidden="true">
        {QBER_TICKS.map((t) => (
          <span key={t} className="absolute -translate-x-1/2 first:translate-x-0 last:-translate-x-full" style={{ left: pos(t) }}>
            {t * 100}%
          </span>
        ))}
      </div>

      <p className="max-w-prose text-small">{summary}</p>
      <p className="max-w-prose text-small text-ink-2">
        The simulated channel has no noise, so any error comes from interception. An intercept-resend attacker
        causes about 25%.
      </p>
    </section>
  )
}

function ChunkProgress({ progress, resumedFrom }) {
  const { chunks_done: done, num_chunks: total, bytes_done: bytes, total_bytes: totalBytes } = progress
  const fraction = total ? done / total : 1
  // Bytes that an earlier attempt already delivered and verified; this attempt does not send them again.
  const resumedFraction = resumedFrom && totalBytes ? Math.min(resumedFrom / totalBytes, 1) : 0
  return (
    <section aria-labelledby="chunks-heading" className="space-y-2">
      <h3 id="chunks-heading" className="font-medium">Encrypted chunks</h3>
      <div
        role="progressbar"
        aria-labelledby="chunks-heading"
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={done}
        aria-valuetext={`${done} of ${total} chunks`}
        className="relative h-2 bg-well"
      >
        <div className="absolute inset-y-0 left-0 bg-ink-2/50" style={{ width: `${resumedFraction * 100}%` }} />
        <div className="relative h-full bg-accent transition-[width] duration-300"
          style={{ marginLeft: `${resumedFraction * 100}%`, width: `${Math.max(fraction - resumedFraction, 0) * 100}%` }} />
      </div>
      <p className="font-mono text-small">
        {done} / {total} chunks, {formatBytes(bytes)} of {formatBytes(totalBytes)}
      </p>
      {resumedFraction > 0 ? (
        <p className="text-small text-ink-2">
          The first {formatBytes(resumedFrom)} were already verified by an earlier attempt and were not sent again.
        </p>
      ) : null}
      <p className="text-small text-ink-2">Each chunk is sealed with AES-256-GCM under its own nonce and checked on arrival.</p>
    </section>
  )
}

export default function ProtocolView({ transfer }) {
  return (
    <div className="space-y-8">
      <StageSequence transfer={transfer} />
      <div className="grid gap-8 2xl:grid-cols-2">
        <KeyFunnel transfer={transfer} />
        <QberScale transfer={transfer} />
      </div>
      {transfer.progress ? <ChunkProgress progress={transfer.progress} resumedFrom={transfer.resumed_from_bytes} /> : null}
    </div>
  )
}
