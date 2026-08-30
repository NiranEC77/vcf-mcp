# Devlog

## 2026-08-30 — count the list in the door, not in the model

Infra on Tanzu Agent Builder asked how many VMs. `vcf_call` on
`GET /api/vcenter/vm` worked. The spoken number was 231. The list was
about 73. Same miss on 29 Aug: 221 vs 73.

The model was counting fields (`vm`, `name`, `power_state`) not
objects. Agent Builder has no `len()`. The door already shortened big
lists and never said how long they were.

So `count` is now on the result, taken from the full payload before
any shrink. The agent should read that field.
