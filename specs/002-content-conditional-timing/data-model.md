# Data Model: Content-Conditional Timing

## Catalogue route (laboratory `catalogue.json`, version `ati-pf2-catalogue-2`)

| Field | Type | Rule |
|---|---|---|
| `path`, `status`, `pf2_category` | unchanged | unchanged |
| `reading_load` | `"short"`, `"long"` or `null` | Required on every page route; `null` on assets and `/lab/missing` |
| `title` | string | Pages only; plain text |
| `text` | list of strings | Pages only; paragraphs of plain text with no markup, links or personal data |

Reading loads:

| Route | Load |
|---|---|
| `/lab/start` | short |
| `/lab/page/landing` | short |
| `/lab/page/catalog` | long |
| `/lab/page/detail` | long |
| `/lab/page/related` | long |
| `/lab/complete` | short |

## ATI pin

- `PF2_READING_LOAD`: maps each ATI-PF-2 route category to its load (`start`,
  `landing` and `complete` are short; `catalog`, `detail` and `related` are long). Assets
  have none. It is pinned to the laboratory value by the parity test.

## Feature `dwell_ratio_bucket` (family `content_tempo`)

- Dwell of a navigation: the time from that request to the next navigation request.
  Assets are skipped, and the last navigation has no dwell.
- Ratio: the mean dwell over long pages divided by the mean dwell over short pages.
- Bucket: below 1.0 is 0, below 2.0 is 1, below 3.5 is 2, otherwise 3. It is also 0 when
  either mean is missing or not positive.

## Scenario versions (laboratory executor)

| Version | Assets | Participant sees | Prompts |
|---|---|---|---|
| `ati-pf2-1.0` | paced like any step | the next route | every step |
| `ati-pf2-1.1` | right after their page | each page's text | navigations only |

## Simulation options (ATI)

- `SimulatedScenario`: `keypress` (default, today's corpora) or `reading`.
- `AutomationPauseModel` gains `imitate-content`. In `reading`, `imitate` is the
  distribution mimic and `imitate-content` the content-aware mimic. `imitate-content`
  requires `reading`.
