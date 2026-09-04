import { describe, expect, it } from 'vitest'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

const raw = (p: string) => readFile(join(__dirname, '..', p), 'utf8')
// Strip comments before matching. The rules below are explained in prose that
// quotes the very class names and style keys being asserted against, so a
// raw-text negative match (`fixed inset-0 z-[46]`, `top-safe-offset-[42px]`)
// hits the comment that documents the change rather than the code.
const src = async (p: string) =>
  (await raw(p)).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1')

// The same keyboard-stranding mechanism the command palette was pinned against
// (visualViewportKeyboard.test.ts) reaches every `fixed inset-0` overlay with a
// focused input. The mobile sessions drawer is the residual surface the issue
// named: its scrim was `fixed inset-0` and its panel took its vertical extent
// from `top-safe-offset-[42px]` / `bottom-safe` layout-viewport insets, neither
// of which iOS Safari shrinks for the keyboard. This pins the fix in the same
// source-text style, so a revert to either fails loudly.
describe('mobile sessions drawer overlay', () => {
  it('consumes the shared visual-viewport hook', async () => {
    const s = await src('pages/ChatPage.tsx')
    expect(s, 'expected the hook').toContain('useVisualViewport()')
  })

  it('pins the scrim to the visual viewport rather than inset-0', async () => {
    const s = await src('pages/ChatPage.tsx')
    expect(s).toMatch(/className="fixed left-0 right-0 z-\[46\]/)
    // The scrim's box now follows the visible band. `inset-0` would measure the
    // layout viewport again, which the keyboard does not shrink on iOS.
    expect(s).toMatch(/top: vv\.offsetTop, height: vv\.height/)
    expect(s, 'inset-0 would measure the layout viewport again')
      .not.toMatch(/className="fixed inset-0 z-\[46\]/)
  })

  it('derives the panel vertical extent from the visual viewport, not the safe-offset insets', async () => {
    const s = await src('pages/ChatPage.tsx')
    // Scoped to the sessions drawer's OverlayDrawer element, not the whole file:
    // OTHER mobile surfaces in ChatPage (the floating open-sessions button, the
    // right-side inline overlay) legitimately keep `top-safe-offset-[42px]`, so a
    // file-wide negative match would always fail on code that is not this panel.
    const start = s.indexOf('<OverlayDrawer open=')
    expect(start, 'expected the sessions drawer element').toBeGreaterThan(0)
    const call = s.slice(start, start + 1200)
    // top/height come from vv (px off the visual viewport) plus the env() safe
    // insets and the 42px header gap — a calc, not a `vh`.
    expect(call).toMatch(/top: `calc\(\$\{vv\.offsetTop\}px \+ env\(safe-area-inset-top\) \+ 42px\)`/)
    expect(call).toMatch(/height: `calc\(\$\{vv\.height\}px[^`]*\)`/)
    // The panel no longer takes its vertical extent from the layout-viewport
    // safe-offset / bottom-safe insets…
    expect(call, 'the layout-viewport top inset must be gone from the mobile panel')
      .not.toMatch(/top-safe-offset-\[42px\]/)
    expect(call, 'the layout-viewport bottom inset must be gone from the mobile panel')
      .not.toMatch(/bottom-safe(?![-\w])/)
    // …while the horizontal safe inset stays: only the VERTICAL anchoring moved.
    expect(call).toMatch(/mobile-sessions-overlay fixed left-safe/)
  })
})

describe('OverlayDrawer slide-mode style merge', () => {
  it('keeps x as the sole transform owner and merges the vertical pin without overriding width/x', async () => {
    const s = await src('components/OverlayDrawer.tsx')
    // `slideStyle` is spread FIRST, then width and x, so the caller's vertical
    // pin can never displace the horizontal slide the compositor owns.
    expect(s).toMatch(/style=\{\{ \.\.\.slideStyle, width, x: slideX \}\}/)
    expect(s).toContain('slideStyle?: React.CSSProperties')
  })
})
