# WARP Split-Tunnel Exclusions

Real-time voice/video (VoIP, conferencing) works best going **direct**, not
through WARP/Gateway: lower latency/jitter, and you avoid opening the huge UDP
media ranges these apps need in your Gateway network policies.

This file lists what to **exclude** from WARP so that traffic bypasses Cloudflare.
It is WARP *client* configuration (dashboard), **not** part of the automated
`cf_policies_*` scripts.

## How to apply

Cloudflare Zero Trust → **Settings → WARP Client → (your device profile) →
Split Tunnels**. Default mode is **Exclude** (everything goes through WARP except
what's listed). Add both **hostname** and **IP/CIDR** entries from below.

> **Why both domains and IPs?** Domain exclusions reliably cover *signaling*, but
> real-time **media** rides vendor IP ranges that often don't resolve back to
> those hostnames. For solid call quality, exclude the media IP ranges too.
> These ranges change — pull current values from each vendor's page before locking in.

---

## RingCentral

**Domains:** `ringcentral.com`, `rccdn.com`, `ringcentral.biz`

**IP ranges:** `104.245.56.0/21`, `199.68.212.0/22`, `199.255.120.0/22`, `208.87.40.0/22`

**Media:** UDP 20000–64999 (RTP) — very wide, the main reason to split-tunnel it out.

*Source: RingCentral → "Network requirements / IP addresses and ports."*

---

## Microsoft Teams

**Domains:** `teams.microsoft.com`, `*.teams.microsoft.com`, `*.skype.com`,
`*.sfbassets.com`, `login.microsoftonline.com`, `*.msidentity.com`

**Media IP ranges (UDP 3478–3481):** `13.107.64.0/18`, `52.112.0.0/14`, `52.122.0.0/15`

*Source: Microsoft 365 URLs & IP ranges → "Microsoft Teams" (ID 11, "Optimize" category).*

---

## Google Meet

**Domains:** `meet.google.com`, `*.meet.google.com`, `*.gstatic.com`, `*.googleapis.com`

**Media:** UDP 19302–19309. Google recommends **not** pinning by IP (ranges rotate).
If you must scope: `142.250.0.0/15`, `172.217.0.0/16`, `74.125.0.0/16`,
`173.194.0.0/16`, `108.177.0.0/17`, `216.58.192.0/19`.

*Source: Google Meet → "Prepare your network."*

---

## Apple FaceTime (and iMessage / APNs / iCloud)

**Easy win:** exclude Apple's whole netblock **`17.0.0.0/8`** — Apple owns the
entire /8, so this one entry covers FaceTime, iMessage, APNs, and iCloud.

**Domain alternative:** `*.apple.com`, `*.push.apple.com`, `init.ess.apple.com`, `*.icloud.com`

**Media:** UDP 3478–3497 and 16384–16403.

*Source: Apple → "Use Apple products on enterprise networks" (HT210060).*

---

## Quick copy — IP/CIDR exclusions

```
# RingCentral
104.245.56.0/21
199.68.212.0/22
199.255.120.0/22
208.87.40.0/22
# Microsoft Teams (media)
13.107.64.0/18
52.112.0.0/14
52.122.0.0/15
# Apple (FaceTime/iMessage/APNs/iCloud)
17.0.0.0/8
```

## Related

- Not split-tunneled: NAS / Mac mini admin access — reach those over the
  **private network** (Cloudflare Tunnel + WARP-to-Tunnel) by private IP instead.
- The L4 port-block policy (`policies.config.js`) excludes RFC1918/CGNAT, so it
  never interferes with LAN or private-network traffic.
