// Reconciles the custom Gateway policies defined in policies.config.js.
//
// Order (ascending precedence, first-match-wins per layer):
//   Security block  ->  Allow  ->  Content block
//
// Run `DRY_RUN=1 node cf_policies_create.js` first: it prints the full plan and
// every expression WITHOUT touching your account (no API calls at all).

import { getZeroTrustRules, upsertGatewayPolicy } from "./lib/api.js";
import { DRY_RUN } from "./lib/constants.js";
import { notifyWebhook } from "./lib/utils.js";
import { POLICIES } from "./policies.config.js";

const PREFIX = "CGPS Policy - ";
const base = Number.isInteger(POLICIES.precedenceBase)
  ? POLICIES.precedenceBase
  : 2000;

// Build the desired rule set. Empty expressions are skipped so you only get the
// layers you've actually configured.
const desired = [];
const add = (expr, spec) => {
  if (typeof expr === "string" && expr.trim()) desired.push({ ...spec, traffic: expr });
};

// 1. Security block — above allows
add(POLICIES.blockSecurity?.dns,  { name: `${PREFIX}Security (DNS)`,     action: "block", filters: ["dns"],  precedence: base + 0 });
add(POLICIES.blockSecurity?.http, { name: `${PREFIX}Security (HTTP)`,    action: "block", filters: ["http"], precedence: base + 1 });
add(POLICIES.blockSecurity?.l4,   { name: `${PREFIX}Security (Network)`, action: "block", filters: ["l4"],   precedence: base + 2 });

// 2. Allow — trusted apps, between security and content
add(POLICIES.allow?.dns,  { name: `${PREFIX}Allow (DNS)`,  action: "allow", filters: ["dns"],  precedence: base + 10 });
add(POLICIES.allow?.http, { name: `${PREFIX}Allow (HTTP)`, action: "allow", filters: ["http"], precedence: base + 11 });

// 3. Content block — below allows
add(POLICIES.blockContent?.dns,  { name: `${PREFIX}Content (DNS)`,     action: "block", filters: ["dns"],  precedence: base + 20 });
add(POLICIES.blockContent?.http, { name: `${PREFIX}Content (HTTP)`,    action: "block", filters: ["http"], precedence: base + 21 });
add(POLICIES.blockContent?.l4,   { name: `${PREFIX}Content (Network)`, action: "block", filters: ["l4"],   precedence: base + 22 });

if (POLICIES.safeSearch) {
  console.log(
    "NOTE: safeSearch is enabled in config but not yet applied by this script " +
      "(pending confirmation of the exact API). Enable it in the dashboard for now.\n"
  );
}

if (!desired.length) {
  console.log("No policies configured. Fill in policies.config.js and re-run.");
  process.exit(0);
}

console.log(`Planned ${desired.length} policy rule(s):`);
for (const p of desired) {
  console.log(`  [prec ${p.precedence}] ${p.action.toUpperCase().padEnd(5)} ${p.filters[0].padEnd(4)}  ${p.name}`);
}

if (DRY_RUN) {
  console.log("\nDRY_RUN — no changes made. Expressions that would be applied:\n");
  for (const p of desired) {
    console.log(`### ${p.name}  (${p.action}, ${p.filters[0]})`);
    console.log(p.traffic);
    console.log("");
  }
  console.log("Dry run complete. Unset DRY_RUN to apply.");
  process.exit(0);
}

// Fetch existing rules once so upserts don't each re-list.
const { result: existingRules } = await getZeroTrustRules();

for (const p of desired) {
  const outcome = await upsertGatewayPolicy(p, existingRules);
  console.log(`${outcome}: ${p.name}`);
}

await notifyWebhook(`CGPS Gateway policies reconciled (${desired.length} rules)`);

console.log(
  "\nDone. Verify ORDER in the dashboard (Gateway -> Firewall Policies):\n" +
    "  Security must sit ABOVE Allow, and Allow ABOVE Content.\n" +
    "  Also decide where your existing 'CGPS Filter Lists' rule should sit relative to Allow."
);
