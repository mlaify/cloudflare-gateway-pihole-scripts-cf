// Cloudflare Worker entry point for CGPS.
//
// Runs the full "download -> process -> sync lists -> upsert rule" pipeline on a
// Cron Trigger (see wrangler.toml), entirely in-memory (Workers have no disk).
// Configuration is read from Wrangler vars/secrets via `process.env`, which the
// `nodejs_compat` flag populates, so the shared lib/* modules work unchanged.

import {
  getZeroTrustLists,
  synchronizeZeroTrustLists,
  upsertZeroTrustDNSRule,
  upsertZeroTrustSNIRule,
} from "./lib/api.js";
import {
  BLOCK_BASED_ON_SNI,
  DRY_RUN,
  LIST_ITEM_LIMIT,
  LIST_ITEM_SIZE,
  RECOMMENDED_ALLOWLIST_URLS,
  RECOMMENDED_BLOCKLIST_URLS,
  USER_DEFINED_ALLOWLIST_URLS,
  USER_DEFINED_BLOCKLIST_URLS,
} from "./lib/constants.js";
import { createListProcessor } from "./lib/process.js";
import { notifyWebhook, wait } from "./lib/utils.js";

const allowlistUrls = USER_DEFINED_ALLOWLIST_URLS || RECOMMENDED_ALLOWLIST_URLS;
const blocklistUrls = USER_DEFINED_BLOCKLIST_URLS || RECOMMENDED_BLOCKLIST_URLS;

/**
 * Fetches a source list, tolerating failures.
 *
 * Source lists are third-party and occasionally 404, move or time out. For an
 * unattended job, one bad URL must not abort the whole run, so this returns
 * `null` (and logs) instead of throwing. Client errors (4xx except 429) are not
 * retried since they won't fix themselves; transient errors get a few attempts.
 * @param {string} url
 * @param {(msg: string) => void} log
 * @param {number} [attempts]
 * @returns {Promise<string|null>}
 */
const fetchTextSafe = async (url, log, attempts = 3) => {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.text();

      if (res.status >= 400 && res.status < 500 && res.status !== 429) {
        log(`Skipping ${url} - HTTP ${res.status} (not retryable).`);
        return null;
      }
      throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      if (attempt === attempts) {
        log(`Skipping ${url} after ${attempts} attempt(s) - ${err?.message || err}`);
        return null;
      }
      await wait(1000 * attempt);
    }
  }
  return null;
};

/**
 * Runs the full sync pipeline.
 * @param {(msg: string) => void} [log] Where to send progress messages.
 * @returns {Promise<Object>} A summary of what happened.
 */
async function runSync(log = console.log) {
  const startedAt = Date.now();

  // 1. Allowlists are small; fetch and concatenate them up front so every
  //    blocklist entry can be checked against the full allowlist.
  log(`Downloading ${allowlistUrls.length} allowlist(s)...`);
  let allowlistText = "";
  let allowlistOk = 0;
  for (const url of allowlistUrls) {
    const text = await fetchTextSafe(url, log);
    if (text != null) {
      allowlistText += text + "\n";
      allowlistOk++;
    }
  }
  log(`Loaded ${allowlistOk}/${allowlistUrls.length} allowlist(s).`);

  const processor = createListProcessor({
    allowlistText,
    limit: LIST_ITEM_LIMIT,
    // Disable the normalize cache to keep peak memory under the 128 MB ceiling.
    memoizeNormalization: false,
  });
  allowlistText = ""; // free the raw allowlist text

  // 2. Blocklists can be huge. Fetch, process and discard them one at a time to
  //    keep peak memory well under the Worker's 128 MB ceiling.
  log(`Downloading and processing ${blocklistUrls.length} blocklist(s)...`);
  let blocklistOk = 0;
  for (const url of blocklistUrls) {
    if (processor.isFull()) {
      log(`Domain limit (${LIST_ITEM_LIMIT}) reached - skipping remaining lists.`);
      break;
    }
    let text = await fetchTextSafe(url, log);
    if (text != null) {
      processor.addBlocklistText(text);
      blocklistOk++;
    }
    text = null; // drop the reference before fetching the next list
  }
  log(`Loaded ${blocklistOk}/${blocklistUrls.length} blocklist(s).`);

  const { domains, stats } = processor.result();

  // Safety guard: never sync an empty (or suspiciously empty) result. If every
  // blocklist failed to download, syncing would remove every blocked domain and
  // effectively disable filtering. Abort instead and leave the account as-is.
  if (blocklistOk === 0 || domains.length === 0) {
    throw new Error(
      `Refusing to sync: ${domains.length} domains from ${blocklistOk}/${blocklistUrls.length} blocklists. ` +
        `This usually means the source lists were unreachable; leaving existing lists untouched.`
    );
  }
  const numberOfLists = Math.ceil(domains.length / LIST_ITEM_SIZE);

  log(
    `Processed ${stats.processedDomainCount} domains -> ${domains.length} blocked ` +
      `(${stats.duplicateDomainCount} duplicate, ${stats.unnecessaryDomainCount} redundant, ` +
      `${stats.allowedDomainCount} allowlisted) across ${numberOfLists} list(s).`
  );

  if (DRY_RUN) {
    log("DRY_RUN is set - no changes were made to Cloudflare.");
    return { dryRun: true, numberOfLists, ...stats, ms: Date.now() - startedAt };
  }

  // 3. Reconcile the Zero Trust lists with the desired domains.
  await synchronizeZeroTrustLists(domains);

  // 4. Ensure the Gateway rule(s) point at the current lists.
  const { result: lists } = await getZeroTrustLists();
  await upsertZeroTrustDNSRule(lists, "CGPS Filter Lists");
  if (BLOCK_BASED_ON_SNI) {
    await upsertZeroTrustSNIRule(
      lists,
      "CGPS Filter Lists - SNI Based Filtering"
    );
  }

  const summary = { dryRun: false, numberOfLists, ...stats, ms: Date.now() - startedAt };
  await notifyWebhook(
    `CGPS Worker sync complete: ${domains.length} domains across ${numberOfLists} lists.`
  );
  return summary;
}

export default {
  /**
   * Cron Trigger handler. This is the main, unattended entry point.
   */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      runSync().catch(async (err) => {
        console.error("CGPS Worker sync failed:", err);
        await notifyWebhook(
          `CGPS Worker sync FAILED: ${err?.message || err}`
        );
        throw err;
      })
    );
  },

  /**
   * Optional manual trigger + health check.
   *   GET  /health        -> "ok"
   *   POST /run?token=XXX  -> starts a sync (requires TRIGGER_TOKEN secret)
   * The run is kicked off in the background; watch progress with `wrangler tail`
   * or your Discord webhook. This avoids the shorter fetch-handler time budget.
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response("ok\n", { status: 200 });
    }

    if (url.pathname !== "/run") {
      return new Response(
        "CGPS Worker.\nGET /health to check status.\nPOST /run?token=<TRIGGER_TOKEN> to force a sync.\n",
        { status: 404 }
      );
    }

    const expected =
      env?.TRIGGER_TOKEN ??
      (typeof process !== "undefined" ? process.env.TRIGGER_TOKEN : undefined);

    if (!expected) {
      return new Response(
        "Manual trigger disabled. Set the TRIGGER_TOKEN secret to enable it.\n",
        { status: 403 }
      );
    }

    const provided =
      url.searchParams.get("token") ||
      (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");

    if (provided !== expected) {
      return new Response("Forbidden\n", { status: 403 });
    }

    ctx.waitUntil(
      runSync().catch(async (err) => {
        console.error("CGPS Worker manual sync failed:", err);
        await notifyWebhook(
          `CGPS Worker manual sync FAILED: ${err?.message || err}`
        );
      })
    );

    return new Response(
      "Sync started. Watch progress with `wrangler tail` or your webhook.\n",
      { status: 202 }
    );
  },
};
