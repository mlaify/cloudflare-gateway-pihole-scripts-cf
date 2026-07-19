// Declarative config for custom Cloudflare Gateway policies, reconciled by
// cf_policies_create.js / cf_policies_delete.js.
//
// Every rule is named "CGPS Policy - <name>" so it's identifiable and the delete
// script removes exactly what it created, never touching rules you made by hand.
//
// ORDER (Gateway is first-match-wins per layer, ascending `precedence`):
//   1. Security block   (threat signals — never bypassed)     <- precedenceBase + 0..2
//   2. Allow            (trusted apps exempt from content)     <- precedenceBase + 10..11
//   3. Content block    (categories, geo, TLDs, trackers)      <- precedenceBase + 20..22
//
// After the first apply, VERIFY the order in the dashboard (Gateway → Firewall
// Policies) — especially whether these should sit above or below your existing
// "CGPS Filter Lists" (the ultimate-blocklist) rule.

export const POLICIES = {
  // Base precedence for this rule set. Lower = evaluated earlier. If the API
  // rejects a value as already-in-use, bump this (e.g., to 2100) and re-run.
  precedenceBase: 2000,

  // ===========================================================================
  // ALLOW — trusted apps/services, evaluated between the security and content
  // blocks. Generate these expressions ONCE from the dashboard, then paste:
  //   Gateway → Firewall Policies → DNS (then HTTP) → Create policy →
  //   build a rule selecting your Applications / Application Types + any domains
  //   via the picker → switch to the "Expression Editor" → copy the expression.
  // The picker fills in the exact app IDs, which is more reliable than name
  // guessing. Leave "" to skip that layer (no allow rule created).
  //
  // Target list to select in the picker (your words, for reference):
  //   Application Types: AI, Developer Services, Business, Education, Email,
  //     Collaboration, Productivity, Security/MDM, Social Networking
  //   Apps: Signal, Slack, Jamf, 1Password, Bitwarden, RingCentral,
  //     Microsoft 365, Google Workspace, Gmail, Proton Mail, Proton VPN, Apple, iCloud
  //   Domains: bsky.app, bsky.social, verizon.com, verizonwireless.com, vzw.com
  // ===========================================================================
  allow: {
    dns: "",   // paste DNS allow expression here
    http: "",  // paste HTTP allow expression here
  },

  // SafeSearch on search engines. NOTE: not created by the script yet — the
  // exact API mechanism needs confirming. For now, enable it in the dashboard
  // (Gateway → Firewall Policies → DNS → add a policy with the "Safe Search"
  // setting on search-engine apps), or say the word and I'll wire it up.
  safeSearch: true,

  // ===========================================================================
  // SECURITY BLOCK — threat signals only. Placed ABOVE the allow rules so even
  // allowed apps can't reach known-malicious infrastructure. (Split out of your
  // original expressions.)
  // ===========================================================================
  blockSecurity: {
    dns: `any(dns.domains[*] in {"pmbmonetize.live" "sync.pmbmonetize.live" "sync.contextualadv.com" "contextualadv.com" "usbrowserspeed.com" "a.usbrowserspeed.com"}) or any(dns.security_category[*] in {178 80 187 83 176 175 117 131 188 134 191 151 153})`,

    http: `any(http.request.uri.security_category[*] in {178 80 187 83 176 175 117 131 188 134 191 151 153}) or any(http.request.domains[*] in {"pmbmonetize.live" "sync.pmbmonetize.live" "sync.contextualadv.com" "contextualadv.com" "usbrowserspeed.com" "a.usbrowserspeed.com"})`,

    l4: `any(net.fqdn.security_category[*] in {178 80 187 83 176 175 117 131 188 134 191 151 153})`,
  },

  // ===========================================================================
  // CONTENT BLOCK — content categories, geo, TLDs, trackers, tpkt. Placed BELOW
  // the allow rules so trusted apps are exempt. (Split out of your originals.)
  // ===========================================================================
  blockContent: {
    dns: `any(dns.content_category[*] in {66 183 99 17 85 87 102 157 135 138 180 162 32 169 177 128 158 165 166 1 195 179 33 181 2 67 125 133}) or any(dns.domains[*] matches "[.](cn|ru)$") or any(dns.dst.geo.country[*] in {"AF" "BY" "CF" "CN" "CG" "CD" "CU" "CY" "ER" "ET" "HT" "HK" "IR" "IQ" "KP" "LB" "LY" "ML" "MM" "NI" "RU" "SO" "SS" "SD" "SY" "UA" "VE" "YE" "ZW"}) or any(dns.domains[*] matches "[.](rest|hair|top|live|cfd|boats|beauty|mom|skin|okinawa)$") or any(dns.domains[*] matches "[.](zip|mobi)$") or any(dns.domains[*] matches "(mtgglobals|moloco|adtracker|advert|adserv|adsystem|doubleclick|2mdn|truecaller|uberads|206ads|360in|360yield|3lift|a2z|aarki|ad2iction|adcolony|addthis|adform|adhaven|adlooxtracking|admicro|adnxs|adpushup|adroll|adsafeprotected|adsbynimbus|adspruce|adsrvr|adswizz|adtelligent|adventori|adzerk|aerserv|amplitude|aniview|anzuinfra|apester|aralego|atdmt|atwola|bannersnack|batmobi|bluecava|blueconic|carambo|casalemediacriteo|crittercismriteo|crittercism|revcontent|ijinshan|imrworldwide|inmobi|marketo|moatads|moatpixel|mookie|perfectaudience|permutive|pubmatic|pushwoosh|rayjump|revcontent|revjet|rfihub|richrelevance|rqmob|rubiconproject|onetag|samba|scopely|scorecardresearch|shareaholic|sharethis|sharethrough|smaato|snapads|speedshiftmedia|supersonicads|swrve|taboola|tremorhub|unity3d|vertamedia|videohub|vungle|wzrkt|xiaomi|yieldlove|yieldmo|yieldoptimizer|baidu|chinanet|googlesyndication)")`,

    http: `any(http.request.uri.content_category[*] in {66 183 99 17 85 87 102 157 135 138 180 162 32 169 177 128 158 165 1 195 33 179 166 181 2 67 125 133}) or any(http.request.domains[*] matches "[.](cn|ru)$") or http.dst_ip.geo.country in {"AF" "BY" "CF" "CN" "CG" "CD" "CU" "CY" "ER" "ET" "HT" "HK" "IR" "IQ" "KP" "LB" "LY" "ML" "MM" "NI" "RU" "SO" "SS" "SD" "SY" "UA" "VE" "YE" "ZW"} or any(http.request.domains[*] matches "[.](rest|hair|top|live|cfd|boats|beauty|mom|skin|okinawa)$") or any(http.request.domains[*] matches "[.](zip|mobi)$") or any(http.request.domains[*] matches "(mtgglobals|moloco|adtracker|advert|adserv|adsystem|doubleclick|2mdn|truecaller|uberads|206ads|360in|360yield|3lift|a2z|aarki|ad2iction|adcolony|addthis|adform|adhaven|adlooxtracking|admicro|adnxs|adpushup|adroll|adsafeprotected|adsbynimbus|adspruce|adsrvr|adswizz|adtelligent|adventori|adzerk|aerserv|amplitude|aniview|anzuinfra|apester|aralego|atdmt|atwola|bannersnack|batmobi|bluecava|blueconic|carambo|casalemediacriteo|crittercismriteo|crittercism|revcontent|ijinshan|imrworldwide|inmobi|marketo|moatads|moatpixel|mookie|perfectaudience|permutive|pubmatic|pushwoosh|rayjump|revcontent|revjet|rfihub|richrelevance|rqmob|rubiconproject|onetag|samba|scopely|scorecardresearch|shareaholic|sharethis|sharethrough|smaato|snapads|speedshiftmedia|supersonicads|swrve|taboola|tremorhub|unity3d|vertamedia|videohub|vungle|wzrkt|xiaomi|yieldlove|yieldmo|yieldoptimizer|baidu|chinanet|googlesyndication)")`,

    l4: `any(net.fqdn.content_category[*] in {66 183 99 17 85 87 102 157 135 138 180 162 32 169 177 128 165 1 195 33 179 166 181 158 2 67 125 133}) or net.dst.geo.country in {"AF" "BY" "CF" "CN" "CG" "CD" "CU" "CY" "ER" "ET" "HT" "HK" "IR" "IQ" "KP" "LB" "LY" "ML" "MM" "NI" "RU" "SO" "SS" "SD" "SY" "UA" "VE" "YE" "ZW"} or net.detected_protocol == "tpkt"`,
  },

  // ===========================================================================
  // L4 PORTS — allow only necessary ports, then deny the rest. (You're sending
  // the full list.) Known needs: Synology DSM(5000/5001)/SMB(445)/SSH(22),
  // Mac mini SSH(22)+Screen Sharing(5900), RingCentral, plus web/DNS baseline.
  // The deny-all rule stays DISABLED until you confirm the allow list.
  // ===========================================================================
  l4Ports: {
    allow: {
      // tcp: [22, 80, 443, 445, 5000, 5001, 5900],
      // udp: [53, 443],
    },
    denyAllOthers: false,
  },
};
