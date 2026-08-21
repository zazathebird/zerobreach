# F6 — Phases 153-156: the LAN band (opt-in, read-only)

**Priority 6.** `ADVERSARY_ANALYSIS.md` §B5. Size: M.

Nothing in 133 phases looks off-box. In the lab being built for this tool — a private network of
deliberately infected peers — this is the difference between "patient zero looks clean" and
"patient zero is being poisoned by the machine next to it".

## ⚠ Gating — read this before writing a line

This is **the only code in ZeroBreach that touches a machine other than the one it runs on.** An
IR tool that port-scans a client's production network unprompted is an incident of its own, and
it will get the tool banned from the fleet.

Requirements, all of them mandatory:

- Gated on `$PhasePlan.Hunt` **and** a new `-ScanLan` switch. **Default off.** Add the switch to
  the loader `param()` block — that is the one loader edit you are authorised to make, and keep it
  to exactly that one line plus a `$global:ZB_SCAN_LAN` assignment.
- **Read-only.** Never write to a peer, never authenticate with credentials, never mount a share.
- **Rate-limited** and bounded: the ARP-cache neighbour set only, a hard cap on hosts, a
  wall-clock budget like the existing `SCAN_DEADLINE_S`.
- Refuse to run if the local subnet is larger than /22 — that is a datacentre, not an office, and
  someone has misconfigured something.
- Print exactly what it is about to do, and what it will not do, before it does it.

## Phase 153 — Name-resolution poisoning (Responder / Inveigh)

**The highest-value detection in this task and one of the cheapest anywhere in the tool.**

Broadcast an LLMNR and an NBT-NS query for a hostname that **cannot exist** (a random 16-character
string). On a healthy network nothing answers. A poisoner answers everything, so **any response is
proof**, with essentially no false-positive rate and no reliance on a signature.

Repeat for mDNS. Record the responding IP and MAC — that is the attacker's machine, and on this
lab network it will be one of the peers.

## Phase 154 — Rogue DHCP / IPv6 takeover

- Two DHCP offers for one discover → rogue DHCP.
- A router advertisement or DHCPv6 server on a network with no legitimate IPv6 deployment →
  `mitm6`. Correlate: has the machine's DNS server just become a link-local IPv6 address?

## Phase 155 — ARP / gateway integrity

One MAC claiming several IPs; the gateway's MAC changing during the scan; a MAC whose OUI is
locally-administered. Read `Get-NetNeighbor` (or `arp -a` as fallback) twice, spaced, and diff.

## Phase 156 — Peer exposure sweep

For each ARP-cache neighbour, and only with `-ScanLan`: SMB signing not required, SMBv1 enabled,
null-session-readable shares, RDP without NLA, WinRM listening, unauthenticated admin shares.

This answers "what can patient zero reach", which is the question an MSP actually gets asked after
an incident. Connect, read the banner/negotiation, disconnect. **No authentication attempts** —
a failed auth against a domain account will lock it out and you will have caused an outage.

## Deliverables

Phases 153-156, the `-ScanLan` switch, signature keys, and tests proving the band is **completely
inert** without `-ScanLan` (assert zero network calls and zero findings). That test is the most
important one in this task.
