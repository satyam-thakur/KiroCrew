/**
 * Switching BACK to a slot must not re-fetch the whole transcript.
 *
 * The switch used to go unbounded for any slot with rows already painted, and
 * the comment beside it carried the measurement: 6.2MB/~1s unbounded against
 * 0.7MB/57ms bounded. So a session was fast the first time it was opened and
 * slow every time after — the reported "switching chats got slow and janky",
 * worst on the largest sessions.
 *
 * What the unbounded shape actually protected against is a HOLE: a window
 * sitting entirely newer than the cache leaves a gap mid-transcript. That is a
 * coverage question, so these pins fix the two halves separately — the bound asks
 * for exactly what the tab already holds, and the retry fires on GROWTH large
 * enough to clear that window, not on the response's size.
 *
 * The bound must not buy headroom. The window extends BACKWARD from the newest
 * row, so every spare row is a row of OLDER history nobody asked for; asking for
 * the cache plus a page grew the transcript upward on every revisit, and because
 * the next revisit measures the cache it just grew, it ratcheted one page per
 * switch to the handler ceiling. Reported from a phone as history loading itself
 * on every session switch, from a reader parked at the live end — with no gesture
 * and no spinner, since this path never sets `loadingOlder` and so is invisible
 * to every guard on the automatic older-history doors.
 */
import { describe, it, expect } from 'vitest'
import {
  slotSwitchFetchLimit,
  slotSwitchNeedsUnboundedRetry,
  OLDER_PAGE_LIMIT,
  SLOT_DETAIL_MAX_LIMIT,
} from '../store/chatSlice'

describe('slotSwitchFetchLimit', () => {
  it('bounds a fresh slot to one page', () => {
    expect(slotSwitchFetchLimit({ streaming: false, cached: 0 })).toBe(OLDER_PAGE_LIMIT)
  })

  it('keeps a streaming slot unbounded', () => {
    // A streaming slot's tail moves under the window, which is the one case a
    // bound genuinely cannot track.
    expect(slotSwitchFetchLimit({ streaming: true, cached: 0 })).toBeUndefined()
    expect(slotSwitchFetchLimit({ streaming: true, cached: 4000 })).toBeUndefined()
  })

  it('bounds a PAINTED idle slot to exactly the cache, so a revisit loads no older history', () => {
    // Not `cached + a page`: the window runs backward from the newest row, so a
    // page of headroom IS a page of older history, fetched on every revisit and
    // ratcheting upward because the next revisit measures the grown cache.
    expect(slotSwitchFetchLimit({ streaming: false, cached: 120 })).toBe(120)
    // A revisit of the grown cache asks for the grown cache -- and nothing more,
    // so the transcript stops climbing instead of walking to the ceiling.
    expect(slotSwitchFetchLimit({ streaming: false, cached: 220 })).toBe(220)
  })

  it('still asks for a whole page when the cache is smaller than one', () => {
    // A handful of painted rows must not shrink the window below the page every
    // other path uses, or the first switch would serve less than a fresh open.
    expect(slotSwitchFetchLimit({ streaming: false, cached: 3 })).toBe(OLDER_PAGE_LIMIT)
  })

  it('never asks past the handler ceiling, which would be clamped silently', () => {
    // chat_handlers clamps with `min(int(limit), 500)`, so asking for more would
    // make the requested limit a lie the coverage check then reasons from.
    expect(slotSwitchFetchLimit({ streaming: false, cached: 5000 })).toBe(SLOT_DETAIL_MAX_LIMIT)
  })
})

describe('slotSwitchNeedsUnboundedRetry', () => {
  const base = { requestedLimit: 200, cached: 100, serverTotal: 900, priorServerTotal: 900 }

  it('does not retry when the slot did not grow while this tab was away', () => {
    expect(slotSwitchNeedsUnboundedRetry(base)).toBe(false)
  })

  it('does not retry for growth smaller than the window just requested', () => {
    expect(slotSwitchNeedsUnboundedRetry({ ...base, serverTotal: 900 + 199 })).toBe(false)
  })

  it('retries once when growth could have cleared the window', () => {
    // 200 new rows against a 200-row window: the oldest row returned may be
    // newer than the newest cached row, which is the hole.
    expect(slotSwitchNeedsUnboundedRetry({ ...base, serverTotal: 900 + 200 })).toBe(true)
  })

  it('retries when overlap cannot be proven, rather than guessing', () => {
    expect(slotSwitchNeedsUnboundedRetry({ ...base, priorServerTotal: undefined })).toBe(true)
    expect(slotSwitchNeedsUnboundedRetry({ ...base, serverTotal: undefined })).toBe(true)
  })

  it('never retries an already-unbounded fetch, or a fresh slot', () => {
    expect(slotSwitchNeedsUnboundedRetry({ ...base, requestedLimit: undefined })).toBe(false)
    expect(slotSwitchNeedsUnboundedRetry({ ...base, cached: 0 })).toBe(false)
  })
})
