# Devlog

## 2026-09-17 — slim the list so the model can see the count

Talk asked how many datastores. `vcf_search_api` and `vcf_call`
finished. The model said it could see one VSAN row and not the
count, so it would not name the total.

The door already computed `count` before `_fit`. That was not
enough. `_fit` could turn one fat vSAN object into a 20k clipped
JSON string. Agent Builder then shears that blob. The number sits
behind it, or the model treats the fragment as an incomplete array.

`count` and `summary` now lead the reply. Collection rows are
slimmed to identity fields (`name`, `type`, `capacity`, …). A list
item is never replaced with a clipped string. `datastores` and a
one-level nest count as collections.

I did not script the talk agent. The door states the number.

## 2026-08-30 — count the list in the door, not in the model

Infra on Tanzu Agent Builder asked how many VMs. `vcf_call` on
`GET /api/vcenter/vm` worked. The spoken number was 231. The list was
about 73. Same miss on 29 Aug: 221 vs 73.

The model was counting fields (`vm`, `name`, `power_state`) not
objects. Agent Builder has no `len()`. The door already shortened big
lists and never said how long they were.

So `count` is now on the result, taken from the full payload before
any shrink. The agent should read that field.
