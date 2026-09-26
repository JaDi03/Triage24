const MINUTE_MS = 60 * 1000
const HOUR_MS = 60 * MINUTE_MS

/** "23 h 5 min left", "45 min left" or "overdue by 2 h 3 min". */
export function formatRemaining(dueAt: string | Date, now: Date = new Date()): string {
  const diff = new Date(dueAt).getTime() - now.getTime()
  const abs = Math.abs(diff)
  const hours = Math.floor(abs / HOUR_MS)
  const minutes = Math.floor((abs % HOUR_MS) / MINUTE_MS)
  const span = hours > 0 ? `${hours} h ${minutes} min` : `${minutes} min`
  return diff >= 0 ? `${span} left` : `overdue by ${span}`
}

/** Local date and time, e.g. "27 Sept 2026, 10:00". */
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
