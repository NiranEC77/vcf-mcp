# Devlog

## 2026-09-20 — the door was refusing tokens the gateway had already approved

A hosted copy sat behind an agent gateway. An agent was granted one
job — inspect VCF — and its token carried that job as a scope, not a
list of tool names. The gateway accepted it, forwarded it, and this
server answered 401. The gateway then told the agent "backend
unavailable", which pointed everyone at the wrong component for a day.

The bearer check here only knew tool names and the blanket `tools`
scope. It had been written before job scopes existed. So it was doing
the gateway's job, badly, and refusing anything it did not recognise.

The fix is to behave like any MCP server behind a gateway: verify the
token (signature, expiry, audience for this server) and accept a job
scope as a grant. Which tools the job covers is the gateway's decision;
it strips the rest and denies a call outside the job with 403. Tool-name
scopes still work for tokens that carry them.

While here, the HTTP mode that had lived only in the hosted copy came
into the package: `$PORT` or `vcf-mcp serve-http`, static tokens or an
OAuth issuer, RFC 9728 metadata, `/health`, audit to stdout. All of it
from environment variables; no site names in code.

One thing to say plainly: a job scope opens the whole server for a
caller that reaches the backend route directly instead of through the
gateway. That is true of every MCP backend behind a gateway. Keep the
backend route reachable only from the gateway.

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
