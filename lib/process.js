import { LIST_ITEM_LIMIT } from "./constants.js";
import { normalizeDomain } from "./helpers.js";
import {
  extractDomain,
  isComment,
  isValidDomain,
  memoize,
} from "./utils.js";

/**
 * Iterates over the lines of a string without allocating an array for every
 * line up front. This keeps peak memory low when scanning very large blocklists
 * (hundreds of thousands of lines) inside a memory-constrained runtime such as
 * a Cloudflare Worker (128 MB hard limit).
 * @param {string} text The text to scan.
 * @param {(line: string) => boolean | void} onLine Callback per line. Return
 *   `true` to stop iterating early.
 */
export const forEachLine = (text, onLine) => {
  if (!text) return;

  let start = 0;
  const length = text.length;

  while (start <= length) {
    let end = text.indexOf("\n", start);
    if (end === -1) end = length;

    // Trim a trailing \r so CRLF files behave like LF files.
    let lineEnd = end;
    if (lineEnd > start && text.charCodeAt(lineEnd - 1) === 13) lineEnd--;

    const stop = onLine(text.slice(start, lineEnd));
    if (stop === true) return;

    start = end + 1;
  }
};

/**
 * @typedef {Object} ProcessResult
 * @property {string[]} domains The final, deduplicated list of domains to block.
 * @property {Object} stats Counters describing what happened during processing.
 */

/**
 * Creates a stateful list processor.
 *
 * The allowlist is loaded up front; blocklist text is then fed in one chunk at a
 * time via {@link addBlocklistText}. Feeding blocklists incrementally lets a
 * memory-constrained caller (the Worker) fetch, process and discard each source
 * list in turn rather than holding every raw list in memory at once.
 *
 * Behaviour matches `cf_list_create.js` exactly:
 *  - comments and invalid domains are dropped,
 *  - allowlisted domains (and blocklist entries whose parent is allowlisted) are removed,
 *  - exact duplicates and domains already covered by a blocked parent are removed,
 *  - collection stops once `limit` blocked domains have been gathered.
 *
 * @param {Object} params
 * @param {string} params.allowlistText Raw allowlist contents.
 * @param {number} [params.limit] Max number of domains to block. Defaults to LIST_ITEM_LIMIT.
 * @param {boolean} [params.debug] Log per-domain skip reasons.
 * @param {boolean} [params.memoizeNormalization] Cache normalizeDomain results.
 *   Speeds up the CLI slightly, but the cache holds every unique input line, so
 *   memory-constrained callers (the Worker) should disable it. normalizeDomain
 *   is cheap, so disabling it costs little CPU.
 */
export const createListProcessor = ({
  allowlistText = "",
  limit = LIST_ITEM_LIMIT,
  debug = false,
  memoizeNormalization = true,
} = {}) => {
  const allowlist = new Map();
  const blocklist = new Map();
  const domains = [];
  const memoizedNormalizeDomain = memoizeNormalization
    ? memoize(normalizeDomain)
    : normalizeDomain;

  let processedDomainCount = 0;
  let unnecessaryDomainCount = 0;
  let duplicateDomainCount = 0;
  let allowedDomainCount = 0;

  // Read allowlist up front so every blocklist chunk can be checked against it.
  forEachLine(allowlistText, (line) => {
    const _line = line.trim();
    if (!_line) return;
    if (isComment(_line)) return;

    const domain = memoizedNormalizeDomain(_line, true);
    if (!isValidDomain(domain)) return;

    allowlist.set(domain, 1);
  });

  const isFull = () => domains.length >= limit;

  /**
   * Feeds one chunk of blocklist text through the processor.
   * @param {string} text Raw blocklist contents.
   * @returns {boolean} `false` once the domain limit has been reached (further
   *   text can be skipped), otherwise `true`.
   */
  const addBlocklistText = (text) => {
    forEachLine(text, (line) => {
      if (isFull()) return true;

      const _line = line.trim();
      if (!_line) return;
      if (isComment(_line)) return;

      // Remove prefixes and suffixes in hosts, wildcard or adblock format
      const domain = memoizedNormalizeDomain(_line);

      // Skip anything that isn't a bare, valid domain
      if (!isValidDomain(domain)) return;

      processedDomainCount++;

      if (allowlist.has(domain)) {
        if (debug) console.log(`Found ${domain} in allowlist - Skipping`);
        allowedDomainCount++;
        return;
      }

      if (blocklist.has(domain)) {
        if (debug) console.log(`Found ${domain} in blocklist already - Skipping`);
        duplicateDomainCount++;
        return;
      }

      // Get all higher levels of the domain and check from the highest, because
      // blocking a parent domain also blocks all of its subdomains.
      // Example: fourth.third.example.com => ["example.com", "third.example.com", ...]
      for (const item of extractDomain(domain).slice(1)) {
        if (allowlist.has(item)) {
          if (debug) console.log(`Found parent domain ${item} in allowlist - Skipping ${domain}`);
          allowedDomainCount++;
          return;
        }

        if (!blocklist.has(item)) continue;

        // A higher-level domain is already blocked, so this one is redundant.
        if (debug) console.log(`Found ${item} in blocklist already - Skipping ${domain}`);
        unnecessaryDomainCount++;
        return;
      }

      blocklist.set(domain, 1);
      domains.push(domain);

      if (isFull()) return true;
    });

    return !isFull();
  };

  /** @returns {ProcessResult} */
  const result = () => ({
    domains,
    stats: {
      processedDomainCount,
      duplicateDomainCount,
      unnecessaryDomainCount,
      allowedDomainCount,
      blockedDomainCount: domains.length,
    },
  });

  return { addBlocklistText, result, isFull };
};

/**
 * Builds the final blocklist from raw allowlist and blocklist text in one call.
 * Thin wrapper around {@link createListProcessor} used by the CLI.
 *
 * @param {Object} params
 * @param {string} params.allowlistText Raw allowlist contents.
 * @param {string} params.blocklistText Raw blocklist contents.
 * @param {number} [params.limit] Max number of domains to block. Defaults to LIST_ITEM_LIMIT.
 * @param {boolean} [params.debug] Log per-domain skip reasons.
 * @returns {ProcessResult}
 */
export const processLists = ({
  allowlistText,
  blocklistText,
  limit = LIST_ITEM_LIMIT,
  debug = false,
} = {}) => {
  const processor = createListProcessor({ allowlistText, limit, debug });
  processor.addBlocklistText(blocklistText);
  return processor.result();
};
