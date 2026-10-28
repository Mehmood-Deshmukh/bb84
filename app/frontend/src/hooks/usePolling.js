// @ts-check
import { useCallback, useEffect, useState } from 'react'

/**
 * Call `load` now and every `intervalMs`. Keeps the last good data when a call fails.
 *
 * @template T
 * @param {() => Promise<T>} load  must be stable (a module-level function or useCallback)
 * @param {number} intervalMs
 * @returns {{ data: T | undefined, error: Error | null, refresh: () => Promise<void> }}
 */
export function usePolling(load, intervalMs) {
  const [state, setState] = useState(/** @type {{ data: T | undefined, error: Error | null }} */ ({ data: undefined, error: null }))

  const refresh = useCallback(async () => {
    try {
      const data = await load()
      setState({ data, error: null })
    } catch (error) {
      setState((prev) => ({ data: prev.data, error: /** @type {Error} */ (error) }))
    }
  }, [load])

  useEffect(() => {
    let timer = 0
    let stopped = false
    const tick = async () => {
      await refresh()
      if (!stopped) timer = window.setTimeout(tick, intervalMs)
    }
    tick()
    return () => {
      stopped = true
      window.clearTimeout(timer)
    }
  }, [refresh, intervalMs])

  return { ...state, refresh }
}
