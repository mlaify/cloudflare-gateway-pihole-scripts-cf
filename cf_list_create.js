import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { synchronizeZeroTrustLists } from "./lib/api.js";
import {
  DEBUG,
  DRY_RUN,
  LIST_ITEM_LIMIT,
  LIST_ITEM_SIZE,
  PROCESSING_FILENAME,
} from "./lib/constants.js";
import { processLists } from "./lib/process.js";
import { notifyWebhook } from "./lib/utils.js";

const allowlistFilename = existsSync(PROCESSING_FILENAME.OLD_ALLOWLIST)
  ? PROCESSING_FILENAME.OLD_ALLOWLIST
  : PROCESSING_FILENAME.ALLOWLIST;
const blocklistFilename = existsSync(PROCESSING_FILENAME.OLD_BLOCKLIST)
  ? PROCESSING_FILENAME.OLD_BLOCKLIST
  : PROCESSING_FILENAME.BLOCKLIST;

// Check if the blocklist.txt and allowlist.txt files exist
for (const filename of [allowlistFilename, blocklistFilename]) {
  if (!existsSync(filename)) {
    console.error(`File not found: ${filename}. Please create a block/allowlist first, or run download_lists.js to download the recommended lists.`);
    process.exit(1);
  }
}

console.log(`Processing ${allowlistFilename}`);
console.log(`Processing ${blocklistFilename}`);

// The shared processor is filesystem-free so it can be reused by the Worker,
// so we read the files into memory here and hand it the raw text.
const { domains, stats } = processLists({
  allowlistText: readFileSync(resolve(`./${allowlistFilename}`), "utf8"),
  blocklistText: readFileSync(resolve(`./${blocklistFilename}`), "utf8"),
  limit: LIST_ITEM_LIMIT,
  debug: DEBUG,
});

if (stats.blockedDomainCount >= LIST_ITEM_LIMIT) {
  console.log(
    "Maximum number of blocked domains reached - Stopped processing blocklist..."
  );
}

const numberOfLists = Math.ceil(domains.length / LIST_ITEM_SIZE);

console.log("\n\n");
console.log(`Number of processed domains: ${stats.processedDomainCount}`);
console.log(`Number of duplicate domains: ${stats.duplicateDomainCount}`);
console.log(`Number of unnecessary domains: ${stats.unnecessaryDomainCount}`);
console.log(`Number of allowed domains: ${stats.allowedDomainCount}`);
console.log(`Number of blocked domains: ${domains.length}`);
console.log(`Number of lists to be created: ${numberOfLists}`);
console.log("\n\n");

if (DRY_RUN) {
  console.log(
    "Dry run complete - no lists were created. If this was not intended, please remove the DRY_RUN environment variable and try again."
  );
} else {
  console.log(`Creating ${numberOfLists} lists for ${domains.length} domains...`);

  await synchronizeZeroTrustLists(domains);
  await notifyWebhook(
    `CF List Create script finished running (${domains.length} domains, ${numberOfLists} lists)`
  );
}
