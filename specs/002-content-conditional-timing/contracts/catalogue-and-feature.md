# Contract: Catalogue, Feature and CLI

## Catalogue parity (both repositories)

- The laboratory's `tests/test_pf2_catalogue.py` and ATI's
  `tests/evaluation/test_pf2_catalogue_parity.py` pin the same version
  (`ati-pf2-catalogue-2`), the same route categories, and the same reading load per
  category.
- The laboratory's origin test checks that every page body contains its catalogue title
  and every paragraph, and contains no link outside the catalogue.

## ATI model table

The firewall gains family `content_tempo` = (`dwell_ratio_bucket`), so a model table has
70 permitted features in six families. A table without the new column fails closed, as
for any missing feature.

## CLI

`ati pf2-simulate` gains:

| Flag | Values | Default | Errors |
|---|---|---|---|
| `--scenario` | `keypress`, `reading` | `keypress` | argparse choice error |
| `--automation-model` | `timer`, `imitate`, `imitate-content` | `timer` | exit 2 when `imitate-content` is used without `reading` |

The plan JSON gains `scenario`. The executor gains `--scenario-version` with values
`ati-pf2-1.0` (default) and `ati-pf2-1.1`.
