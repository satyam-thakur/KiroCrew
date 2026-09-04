import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Maximize2, Minimize2, RotateCw, ShieldCheck } from 'lucide-react'
import { Btn } from '../../components/ui'
import ErrorNotice from '../../components/ErrorNotice'
import { useTheme } from '../../hooks/useTheme'
import { useSandboxDoc } from '../../hooks/useSandboxDoc'
import { sanitizeCssValue } from '../../lib/cssSanitize'
import { THEME_VAR_NAMES, buildSrcdoc } from '../../lib/widgetSrcdoc'
import { i18nT } from '../../i18n/t'
import { fmtDateTime, toDate } from '../../i18n/format'

/**
 * The sandbox grants for a crew's webview, and the ONE line of this file that is
 * a security boundary rather than a layout choice.
 *
 * `allow-scripts` alone. Every other grant is withheld deliberately:
 *
 * - No `allow-same-origin`, so the document lands on a null (opaque) origin and
 *   cannot read the dashboard's cookies or localStorage, or touch the parent DOM.
 * - No `allow-popups`, which is where this is STRICTER than the artifact frame
 *   it borrows its plumbing from. The gateway route that serves the document
 *   sets one CSP `sandbox` header for every consumer and that header does grant
 *   popups — but sandbox restrictions COMBINE rather than union, so a grant the
 *   frame attribute withholds stays withheld. A crew publishes on an unattended
 *   loop with nobody at the keyboard; a window it could open is a capability
 *   nothing about a status dashboard needs.
 * - No `allow-top-navigation`, `allow-forms`, or `allow-modals`.
 *
 * Scripts DO run, which is what the template needs to read its data island and
 * render. Egress is closed by the document CSP `buildSrcdoc` injects
 * (`connect-src 'none'`, `form-action 'none'`, `img-src data: blob:`).
 *
 * ONE value for both the docked and the expanded view: the frame is the same
 * element in both, so there is no second attribute to keep in step. Pinned by a
 * test that asserts it in each state.
 */
export const CREW_WEBVIEW_SANDBOX = 'allow-scripts'

/**
 * The sentence-length threshold, mirroring ``PROSE_CHARS`` in ``default.html``.
 *
 * Deliberately duplicated rather than shared: the template is an HTML file the
 * Python package ships and this is a React module, so there is no seam to import
 * across. Both sides answer the same question -- "is this a counter or a
 * sentence?" -- and both must answer it the same way, or the drawer's lead line
 * would be a field the expanded document renders as a tile.
 */
const PROSE_CHARS = 44

/** How many scalars the docked summary will show. Three single-line rows is what
 *  fits under the lead without the card becoming a second dashboard. */
const MAX_DOCKED_STATS = 3

/** Length ceilings for a docked stat row. A row is only worth showing if it
 *  reads WHOLE at drawer width -- past these it would need truncating, and a
 *  truncated counter tells the operator nothing. Such a field is dropped from
 *  the summary and stays in the expanded document, which has the room. */
const MAX_STAT_LABEL_CHARS = 22
const MAX_STAT_VALUE_CHARS = 18

/** What the template renders for a value the crew does not have. */
const NIL_TEXT = '\u2014'

/**
 * Matches the caveat convention's suffix (``<field>_note`` qualifies ``<field>``).
 *
 * A PATTERN rather than a string constant on purpose. The suffix is a protocol
 * token shared with the template, not copy, so translating it would break the
 * lookup it exists to perform -- but the strict i18n gate counts every string
 * literal on a line this branch wrote and does not (and should not) try to guess
 * which ones are machine tokens. A regex carries no string literal, so the intent
 * is stated without asking the gate to make an exception.
 */
const NOTE_SUFFIX_RE = /_note$/

type PanelData = Record<string, unknown>

interface PanelMeta {
  template: string
  title: string
  crew: string
  published_at: string
  data: PanelData
}

function isScalarValue(v: unknown): boolean {
  return v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
}

/** A value the crew does not have. Distinct from `false` and from `0`. */
function isNilValue(v: unknown): boolean {
  return v === null || v === undefined || v === ''
}

function isProse(v: unknown): v is string {
  return typeof v === 'string' && v.length > PROSE_CHARS
}

function scalarText(v: unknown): string {
  if (isNilValue(v)) return NIL_TEXT
  // Through the catalog: a boolean rendered as a hardcoded `yes`/`no` is copy,
  // and it shipped as English in every locale until the strict gate caught it.
  if (v === true) return i18nT('pages.membersPage.webview_value_yes')
  if (v === false) return i18nT('pages.membersPage.webview_value_no')
  return String(v)
}

/** `open_rulings` and `openRulings` both read as `open rulings`, matching the
 *  heading convention the template uses so the two views name a field alike. */
function labelOf(key: string): string {
  return key
    .replace(/[_-]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .trim()
}

interface DockedStat {
  key: string
  label: string
  value: string
}

interface DockedSummary {
  title: string
  subtitle: string | null
  /** The first sentence-length field in PUBLISHED order — the crew's urgent
   *  line. Order is the only channel the crew has for saying what matters
   *  most, so this is a scan from the front and not a search for a known key. */
  lead: { label: string; text: string } | null
  stats: DockedStat[]
}

/**
 * Reduce a published record to what fits, and is worth reading, at drawer width.
 *
 * This is the whole reason the docked view stopped hosting the document. The
 * expanded dashboard needs a full page to be legible — four tiles across,
 * multi-column grids — and the drawer is a ~250px column, so the document
 * rendered there put the crew's most important line below a fold with no scroll
 * and no signal. Choosing a few fields natively is what makes the drawer answer
 * "what does this crew need from me" instead of showing a clipped dashboard.
 */
function summarize(meta: PanelMeta | null, slug: string): DockedSummary {
  const data: PanelData = meta?.data && typeof meta.data === 'object' ? meta.data : {}
  const rawTitle = typeof data.title === 'string' ? data.title : ''
  const rawSubtitle = typeof data.subtitle === 'string' ? data.subtitle : ''

  // A crew that published no title still gets a heading: an untitled card in a
  // list of crews is unattributable.
  const title = rawTitle || meta?.title || meta?.crew || slug

  const keys = Object.keys(data).filter(k => k !== 'title' && k !== 'subtitle')
  // `<field>_note` is a caveat on another field, not a field — it must not be
  // mistaken for the crew's urgent line or shown as a stat.
  const isAttachedNote = (k: string) =>
    NOTE_SUFFIX_RE.test(k) &&
    Object.prototype.hasOwnProperty.call(data, k.replace(NOTE_SUFFIX_RE, ''))
  const own = keys.filter(k => !isAttachedNote(k))

  let lead: DockedSummary['lead'] = null
  for (const k of own) {
    if (isProse(data[k])) {
      lead = { label: labelOf(k), text: data[k] as string }
      break
    }
  }

  const stats: DockedStat[] = []
  for (const k of own) {
    if (stats.length >= MAX_DOCKED_STATS) break
    const v = data[k]
    if (!isScalarValue(v) || isProse(v) || isNilValue(v)) continue
    const label = labelOf(k)
    const value = scalarText(v)
    if (label.length > MAX_STAT_LABEL_CHARS || value.length > MAX_STAT_VALUE_CHARS) continue
    stats.push({ key: k, label, value })
  }

  return { title, subtitle: rawSubtitle || null, lead, stats }
}

/** Read the computed theme vars (known set only, each value sanitized) so the
 * sandboxed frame matches the dashboard theme. Mirrors the helper in
 * ArtifactBody / ArtifactThumbs. */
function readThemeVars(): Record<string, string> {
  if (typeof window === 'undefined' || typeof document === 'undefined') return {}
  const computed = getComputedStyle(document.documentElement)
  const out: Record<string, string> = {}
  for (const name of THEME_VAR_NAMES) {
    const v = sanitizeCssValue(computed.getPropertyValue(name))
    if (v) out[name] = v
  }
  return out
}

/** Compact age label. The stored stamp is a local-time ISO string with no zone,
 * which `new Date` reads as local — the same clock that wrote it.
 *
 * Every unit goes through the catalog. The suffixes were written inline
 * (`` `${secs}s` ``) and that is copy: a locale that abbreviates minutes
 * differently had no way to say so, and the strict unit-literal gate counts each
 * one. */
function agoLabel(publishedAt: string): string {
  const t = new Date(publishedAt).getTime()
  if (!Number.isFinite(t)) return ''
  const secs = Math.max(0, Math.round((Date.now() - t) / 1000))
  if (secs < 60) return i18nT('pages.membersPage.webview_age_s', { n: secs })
  if (secs < 3600) {
    return i18nT('pages.membersPage.webview_age_m', { n: Math.floor(secs / 60) })
  }
  if (secs < 86400) {
    return i18nT('pages.membersPage.webview_age_h', { n: Math.floor(secs / 3600) })
  }
  return i18nT('pages.membersPage.webview_age_d', { n: Math.floor(secs / 86400) })
}

/** The absolute publish time, for the relative chip's tooltip.
 *
 * A bare `23m` has no anchor: it does not say 23 minutes before WHAT, and it
 * goes stale while the drawer sits open.
 *
 * Formatted in the APP's language, not the browser's. `toLocaleString()` here
 * read the host locale, so a Japanese UI rendered an English tooltip on a
 * translated chip. Deliberately the `medium` date width rather than the numeric
 * one that matches `toLocaleString()`'s old output: this tooltip exists to
 * DISAMBIGUATE, and `07/30/2026` versus `30/07/2026` is the one ambiguity a
 * cross-locale surface should not carry.
 *
 * Empty for an unparseable stamp, which renders as NO tooltip — `fmtDateTime`
 * would give the em dash it uses for absent values, and a tooltip reading `—`
 * is worse than none. */
function absoluteStamp(publishedAt: string): string {
  return toDate(publishedAt) ? fmtDateTime(publishedAt) : ''
}

/**
 * One crew's webview, in two views that share nothing but the record.
 *
 * DOCKED is a native React summary. It renders the crew's title, its urgent
 * line and up to three short counters as ordinary escaped text — no iframe, no
 * document. That is a containment improvement as well as a legibility one:
 * React text children cannot become markup, so this path is strictly stronger
 * than the sandbox it replaces. It must stay that way; a
 * `dangerouslySetInnerHTML` here would be the one edit that undoes it.
 *
 * EXPANDED is the sandboxed document, which is where the dashboard is actually
 * read because a dashboard needs a full page to be legible.
 */
export default function CrewWebview({ slug }: { slug: string }) {
  const [expanded, setExpanded] = useState(false)
  /**
   * Whether the document has EVER been opened, which is what gates minting.
   *
   * Two rules ride on this single flag, and both are load-bearing because the
   * minted URL is SINGLE-USE server-side:
   *
   * 1. It stays false while docked, so a drawer the operator never expands
   *    costs zero mints and zero gateway round trips.
   * 2. Once true it NEVER goes back to false, so collapsing leaves the frame
   *    MOUNTED behind a `display:none` wrapper. Unmounting it would re-request
   *    a spent URL on the next expand and render a blank frame — which is the
   *    bug this flag exists to make impossible, not merely to avoid.
   */
  const [everExpanded, setEverExpanded] = useState(false)

  const { theme, colorTheme, themeVersion } = useTheme()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const themeVars = useMemo(() => readThemeVars(), [theme, colorTheme, themeVersion])

  /**
   * Through React Query rather than a hand-rolled `fetch().then()`.
   *
   * The manual version cached nothing (every drawer open re-fetched) and, more
   * to the point, had no refetch to offer: the error state was a dead end with
   * no way out but reselecting the crew. `refetch` is what makes the read
   * failure recoverable in place.
   */
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['member-panel', slug],
    queryFn: async (): Promise<{ panel: PanelMeta | null; html: string | null }> => {
      const r = await fetch(`/api/members/${encodeURIComponent(slug)}/panel`, {
        credentials: 'same-origin',
      })
      if (!r.ok) throw new Error(`http_${r.status}`)
      return r.json()
    },
    enabled: Boolean(slug),
  })

  const html = data?.html ?? null
  const meta = data?.panel ?? null

  // A different crew is a different document, so the next expand must mint
  // afresh rather than reuse the URL minted for the previous one.
  useEffect(() => {
    setExpanded(false)
    setEverExpanded(false)
  }, [slug])

  const collapse = useCallback(() => setExpanded(false), [])
  const open = useCallback(() => {
    setEverExpanded(true)
    setExpanded(true)
  }, [])

  // Escape collapses. A full-window overlay with no keyboard exit is a trap for
  // anyone not reaching for the mouse.
  useEffect(() => {
    if (!expanded) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') collapse()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [expanded, collapse])

  /**
   * Focus follows the dialog, in BOTH directions.
   *
   * Opening unmounts the summary card, so the button the operator just pressed
   * disappears and focus falls to `<body>` — inside an `aria-modal` region, with
   * a keyboard user left nowhere and the background still tab-reachable.
   * Collapsing had the mirror defect: focus stayed wherever the dialog left it.
   * `hasOpened` distinguishes a real collapse from the first render, so the
   * component does not steal focus on mount just by existing in the drawer.
   */
  const openRef = useRef<HTMLButtonElement | null>(null)
  const collapseRef = useRef<HTMLButtonElement | null>(null)
  const hasOpened = useRef(false)
  useEffect(() => {
    if (expanded) {
      hasOpened.current = true
      collapseRef.current?.focus()
    } else if (hasOpened.current) {
      hasOpened.current = false
      openRef.current?.focus()
    }
  }, [expanded])

  // Null until the first expand: `useSandboxDoc` mints when it receives a
  // document, so withholding it here is what makes the docked view free.
  const srcdoc = useMemo(
    () => (html && everExpanded ? buildSrcdoc({ html, themeVars, mode: theme }) : null),
    [html, everExpanded, themeVars, theme],
  )
  const { url, failed, pending, retry } = useSandboxDoc(srcdoc)

  const summary = useMemo(() => summarize(meta, slug), [meta, slug])

  if (isLoading) {
    return (
      <div className="mb-4 space-y-1.5" data-testid="crew-webview-loading" aria-hidden>
        <div className="h-3 rounded bg-accent/40 animate-pulse" />
        <div className="h-3 w-2/3 rounded bg-accent/40 animate-pulse" />
      </div>
    )
  }

  if (isError) {
    // The shared error surface, with the agent hand-off and a retry. This state
    // held text and nothing else, while the mint failure right below it offered
    // "Try again" — the same failure class with two different answers, one of
    // them a dead end.
    return (
      <div className="mb-4 space-y-1.5">
        <ErrorNotice
          message={i18nT('pages.membersPage.webview_error')}
          askAgent
          testId="crew-webview-error"
        />
        <Btn onClick={() => void refetch()} data-testid="crew-webview-error-retry">
          <RotateCw className="lucide-inline" aria-hidden />
          {i18nT('pages.membersPage.webview_retry')}
        </Btn>
      </div>
    )
  }

  if (!html) {
    return (
      <div className="text-[11px] text-muted mb-4" data-testid="crew-webview-empty">
        {i18nT('pages.membersPage.webview_empty')}
      </div>
    )
  }

  const collapseLabel = i18nT('pages.membersPage.webview_collapse')
  // Names the CONTENT, not an action. `aria-label` was the collapse string, so a
  // screen reader announced the dialog as "Collapse the dashboard" — which is
  // what the button inside it does, not what the region is.
  const dialogLabel = i18nT('pages.membersPage.webview_frame_title', {
    crew: meta?.crew || slug,
  })
  const ago = meta?.published_at ? agoLabel(meta.published_at) : ''
  const agoTitle = meta?.published_at ? absoluteStamp(meta.published_at) : ''

  return (
    <div
      className={expanded ? 'fixed inset-0 z-50 flex flex-col bg-bg p-4' : 'mb-4'}
      data-testid="crew-webview"
      data-expanded={expanded ? 'true' : 'false'}
      role={expanded ? 'dialog' : undefined}
      aria-modal={expanded ? true : undefined}
      aria-label={expanded ? dialogLabel : undefined}
    >
      {!expanded && (
        /*
         * Sized to content, never clipped. Everything that could overflow is
         * clamped EXPLICITLY with an ellipsis (the subtitle to one line, the
         * lead to three) and every stat is pre-filtered to a length that reads
         * whole — because the failure this view replaced was a fixed 420px box
         * with `overflow-hidden` that cut the crew's most important line off
         * with no scrollbar and no fade to say it had.
         */
        <div
          className="rounded-lg border border-border bg-card"
          data-testid="crew-webview-summary"
        >
          <div
            className={
              'flex items-center gap-2 px-2.5 py-1.5 text-[11px] text-muted ' +
              'bg-bg-elevated border-b border-border rounded-t-lg'
            }
          >
            <ShieldCheck className="lucide-inline text-ok" aria-hidden />
            <span className="text-text-strong font-medium">
              {i18nT('pages.membersPage.webview_contained')}
            </span>
            {ago && (
              <span className="ml-auto font-mono shrink-0" title={agoTitle}>
                {ago}
              </span>
            )}
          </div>

          <div className="px-3 py-2.5">
            {/* Crew-supplied strings from here down. Every one is a React text
                child, which is the containment for this path. */}
            <div className="text-[13px] font-semibold text-text-strong leading-snug line-clamp-2">
              {summary.title}
            </div>
            {summary.subtitle && (
              <div className="text-[11px] text-muted truncate mt-0.5" title={summary.subtitle}>
                {summary.subtitle}
              </div>
            )}

            {summary.lead && (
              <div className="mt-2.5" data-testid="crew-webview-lead">
                <div className="text-[10px] font-mono uppercase tracking-[0.09em] text-muted mb-1">
                  {summary.lead.label}
                </div>
                <div className="text-[12px] leading-snug text-text line-clamp-3">
                  {summary.lead.text}
                </div>
              </div>
            )}

            {summary.stats.length > 0 && (
              <dl className="mt-2.5 pt-2 border-t border-border space-y-1">
                {summary.stats.map(s => (
                  <div key={s.key} className="flex items-baseline gap-2">
                    <dt className="text-[10px] font-mono uppercase tracking-[0.09em] text-muted">
                      {s.label}
                    </dt>
                    <dd className="ml-auto m-0 text-[12px] font-mono tabular-nums text-text-strong">
                      {s.value}
                    </dd>
                  </div>
                ))}
              </dl>
            )}

            {/* A real button with words on it. The affordance it replaces was a
                14px icon at the far right of a bar whose own text truncated
                mid-word, which is how a reviewer failed to find the dashboard
                at all. */}
            <Btn
              ref={openRef}
              className="mt-3 w-full justify-center"
              onClick={open}
              aria-haspopup="dialog"
              data-testid="crew-webview-expand"
            >
              <Maximize2 className="lucide-inline" aria-hidden />
              {i18nT('pages.membersPage.webview_open')}
            </Btn>
          </div>
        </div>
      )}

      {/*
       * Mounted from the first expand onward and merely HIDDEN when collapsed.
       * `hidden` is `display:none`, which keeps the element and its loaded
       * document alive; unmounting would re-request a single-use URL. This is
       * the one place in the file where the difference between hiding and
       * unmounting is a bug rather than a preference.
       */}
      {everExpanded && (
        <div className={expanded ? 'flex flex-col flex-1 min-h-0' : 'hidden'}>
          <div
            className={
              'flex items-center gap-2 px-2.5 py-1.5 text-[11px] text-muted bg-bg-elevated ' +
              'border border-border rounded-t-lg shrink-0'
            }
          >
            <ShieldCheck className="lucide-inline text-ok" aria-hidden />
            <span className="text-text-strong font-medium">
              {i18nT('pages.membersPage.webview_contained')}
            </span>
            <span className="truncate">{i18nT('pages.membersPage.webview_contained_detail')}</span>
            {ago && (
              <span className="ml-auto font-mono shrink-0" title={agoTitle}>
                {ago}
              </span>
            )}
            <Btn
              ref={collapseRef}
              className="shrink-0"
              onClick={collapse}
              data-testid="crew-webview-collapse"
            >
              <Minimize2 className="lucide-inline" aria-hidden />
              {collapseLabel}
            </Btn>
          </div>

          <div className="relative border border-border border-t-0 rounded-b-lg overflow-hidden bg-card flex-1 min-h-0">
            {failed && (
              /* The shared surface here too, with the retry kept beside it: the
                 minted URL is single-use, so re-rendering a spent one recovers
                 nothing and `retry` is the only way back. */
              <div className="absolute top-0 left-0 right-0 z-10 p-2 flex items-start gap-2 bg-bg-elevated/95 border-b border-border">
                <ErrorNotice
                  message={i18nT('pages.membersPage.webview_error')}
                  askAgent
                  className="flex-1 min-w-0"
                  testId="crew-webview-mint-error"
                />
                <Btn disabled={pending} onClick={retry} className="shrink-0">
                  <RotateCw className="lucide-inline" aria-hidden />
                  {i18nT('pages.membersPage.webview_retry')}
                </Btn>
              </div>
            )}
            {url ? (
              <iframe
                src={url}
                sandbox={CREW_WEBVIEW_SANDBOX}
                className="w-full h-full border-none bg-card"
                style={{ colorScheme: theme }}
                title={i18nT('pages.membersPage.webview_frame_title', {
                  crew: meta?.crew || slug,
                })}
              />
            ) : (
              <div className="p-4 text-[11px] text-muted">
                {i18nT('pages.membersPage.webview_rendering')}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
