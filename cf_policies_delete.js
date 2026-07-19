// Deletes every Gateway policy this project created (name starts with
// "CGPS Policy - "). Does NOT touch the DNS blocklist rule ("CGPS Filter Lists")
// or any rule you made by hand.
//
// Run `DRY_RUN=1 node cf_policies_delete.js` to preview what would be removed.

import { deleteZeroTrustRule, getZeroTrustRules } from "./lib/api.js";
import { DRY_RUN } from "./lib/constants.js";
import { notifyWebhook } from "./lib/utils.js";

const PREFIX = "CGPS Policy - ";

const { result: rules } = await getZeroTrustRules();
const mine = (rules || []).filter((r) => r.name?.startsWith(PREFIX));

console.log(`Found ${mine.length} rule(s) named "${PREFIX}...".`);

for (const rule of mine) {
  if (DRY_RUN) {
    console.log(`[dry] would delete: ${rule.name}`);
    continue;
  }
  await deleteZeroTrustRule(rule.id);
  console.log(`Deleted: ${rule.name}`);
}

if (!DRY_RUN && mine.length) {
  await notifyWebhook(`CGPS Gateway policies removed (${mine.length} rules)`);
}
