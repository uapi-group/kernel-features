---
title: "Take `IP_UNICAST_IF` into account for routing decisions"
weight: 110
status: completed
categories:
  - sockets
commit: "0e4d354762ce"
---

[x] `IP_UNICAST_IF` should be taken into account for routing decisions
at UDP `connect()` time (currently it isn't, only `SO_BINDTOINDEX`
is, but that does so much more than just that, and one often
doesn't want that)

**🙇 `0e4d354762cefd3e16b4cff8988ff276e45effc4 ("net-next: Fix
IP_UNICAST_IF option behavior for connected sockets")` 🙇**

**Use-Case:** DNS resolvers that associate DNS configuration with
specific network interfaces (example: `systemd-resolved`) typically
want to preferably route DNS traffic to the per-interface DNS
server via that interface, but not make further restrictions on the
origins or received replies, and all that without
privileges. `IP_UNICAST_IF` fulfills this role fine for TCP, but
for UDP it is not taken into account for the `connect()` routing
decision.
