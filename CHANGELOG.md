# Changelog

Terse, dated. Component — change — verification.

## 2026-09-17

- vcf_call: **list replies lead with `count` + `summary` + slim `items`** — fat vSAN objects no longer become a 20k clipped string that hides the number — verified `pytest tests/test_offline.py -q` 43 passed (`test_call_leads_with_count_and_slims_items`, `test_fit_does_not_clip_a_list_item_to_an_opaque_string`)

## 2026-08-30

- vcf_call: **list replies include `count`** (full length, before `_fit` truncates) so an agent does not count JSON fields — verified `pytest tests/test_offline.py -q` (`test_count_items_*`, `test_count_survives_truncation`)
