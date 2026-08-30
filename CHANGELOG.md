# Changelog

Terse, dated. Component — change — verification.

## 2026-08-30

- vcf_call: **list replies include `count`** (full length, before `_fit` truncates) so an agent does not count JSON fields — verified `pytest tests/test_offline.py -q` (`test_count_items_*`, `test_count_survives_truncation`)
