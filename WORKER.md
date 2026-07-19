# Running CGPS as a Cloudflare Worker

This fork can run the entire CGPS pipeline **on Cloudflare's own edge** on a
schedule — no local machine, GitHub Actions, or Docker host required. A
[Cron Trigger](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
fires the Worker, which downloads the block/allow lists into memory, processes
them, reconciles your Zero Trust lists, and upserts the Gateway rule(s).

The original Node CLI (`npm start`, etc.) still works unchanged — the Worker
just reuses the same `lib/` logic through a filesystem-free code path.

## How it fits your account (Enterprise)

Cloudflare caps a Zero Trust account at **100 lists**, with **5,000 entries per
list on Enterprise** (1,000 on Standard). That's a hard ceiling of **500,000
domains** (100 × 5,000). This fork packs **5,000 per list** via
`CLOUDFLARE_LIST_ITEM_SIZE=5000`, so 500k domains fit in exactly 100 lists.
(Upstream CGPS packs 1,000/list, which would need 500 lists and blow the cap.)

## One-time setup

```sh
# 1. Install deps (includes wrangler)
npm install

# 2. Log in to the Cloudflare account that owns your Zero Trust org
npx wrangler login

# 3. Store your API token as a secret (never commit it)
npx wrangler secret put CLOUDFLARE_API_TOKEN
#    (paste the token with Zero Trust read+edit permissions)

# 4. Store your Cloudflare account ID as a secret
npx wrangler secret put CLOUDFLARE_ACCOUNT_ID
#    (kept as a secret so it stays out of this public repo)

# 5. (Optional) enable the manual /run endpoint
npx wrangler secret put TRIGGER_TOKEN
#    (paste any random string; you'll pass it as ?token=... to force a run)
```

Non-secret config lives in `wrangler.toml` under `[vars]` (limits, block-page/SNI
toggles, and your `BLOCKLIST_URLS`). Edit it there for the Worker — the `.env`
file is only used by the local Node CLI. The account ID and API token are stored
as secrets (step 3–4), not in `wrangler.toml`, so nothing sensitive is committed.

## Deploy

```sh
npx wrangler deploy
```

That uploads the Worker and registers the weekly cron (`0 3 * * 1` — Mondays
03:00 UTC). Change the schedule in `wrangler.toml` under `[triggers]`.

## Run it now / watch it

```sh
# Force a run immediately (requires TRIGGER_TOKEN):
curl -X POST "https://cgps.<your-subdomain>.workers.dev/run?token=YOUR_TRIGGER_TOKEN"

# Stream logs (the run happens in the background):
npx wrangler tail

# Health check:
curl "https://cgps.<your-subdomain>.workers.dev/health"
```

You can also trigger the scheduled handler from the Cloudflare dashboard
(Workers & Pages → your Worker → Triggers → Cron).

## Test safely without changing anything

Set `DRY_RUN = "1"` in `wrangler.toml` `[vars]` (or pass `--var DRY_RUN:1` to
`wrangler dev`) and the Worker downloads + processes the lists and logs what it
*would* do, without touching your account.

```sh
npx wrangler dev --var DRY_RUN:1 --var TRIGGER_TOKEN:localtest --port 8801
# then, in another shell:
curl "http://localhost:8801/cdn-cgi/handler/scheduled"   # runs the pipeline locally
npx wrangler tail   # or read the dev console output
```

## Safety & resilience notes

- **Fail-soft downloads.** If a source list 404s or times out, the Worker logs a
  warning and skips it rather than aborting. If *every* blocklist fails (0
  domains), it refuses to sync so your lists are never wiped by a network blip.
- **Incremental sync.** After the first run, only added/removed domains are
  patched, so weekly runs are cheap and stay well under Cloudflare's
  1,000-subrequests-per-invocation limit.
- **Memory.** Workers have a hard 128 MB limit. Blocklists are fetched and
  processed one at a time (and the normalize cache is disabled) to keep peak
  memory down. If a very large future list ever hits the ceiling, the fallback
  is Cloudflare Workflows (splitting download from sync across steps).
- **CPU.** `wrangler.toml` raises `[limits] cpu_ms` for the ~500k-domain pass.
  If your plan rejects the value on deploy, lower it.

## The 500k ceiling and list order

Lists in `BLOCKLIST_URLS` are consumed **top to bottom until 500k domains are
collected**. Large lists at the top (e.g. hagezi `ultimate` + `tif`) can fill
the entire budget on their own, so lists below them are never loaded. Put the
lists you care about most **first**, or use lighter variants, if you want a mix.
