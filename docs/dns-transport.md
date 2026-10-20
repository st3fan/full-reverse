# Persistent DNS transport

Each configured resolver owns a lazily created UDP transport for each server
endpoint it uses. The system resolver still tries its nameservers in order;
explicit resolvers still receive lookups round-robin. A socket stays connected
to its chosen resolver address until rotation, so hostname-valued resolver
endpoints are resolved when opening a socket rather than for every question.

The existing address concurrency, per-attempt deadlines, retry counts, RCODE
handling, and forward confirmation stay in the lookup engine. This change adds
no send-rate policy, retry queue, or independent ASN-enrichment stage.

## Dispatch and validation

One receiver reads each live socket. Outstanding queries are keyed by the wire
transaction ID. A reply must come from the connected resolver address and port,
set QR, clear the reserved Z bit, match the opcode, and contain exactly one
matching question (case-insensitive name, exact type and class). Malformed,
unmatched, and duplicate packets are ignored without completing a lookup.

The UDP transport owns wire IDs; callers' messages are copied before assigning
them. A buffered reply channel lets the receiver finish without waiting for the
query goroutine. Pending entries are removed after a valid reply, cancellation,
or timeout. A receive failure wakes affected calls with an error. ICMP refusal
and reset errors keep the socket reusable; terminal failures open a replacement
on a subsequent attempt. Normal lookup retries and nameserver
fallback still decide how to handle those errors.

## ID lifetime and bounds

A cryptographically seeded ChaCha8 generator shuffles all 65,536 IDs for each
socket. Every ID is used once on that socket, including IDs for canceled,
timed-out, and failed sends. After the ID pool is spent, new requests wait for
the pending set to empty, then rotate to a new socket before sending. Waiting
respects cancellation and the attempt deadline.

The replacement is opened while the previous socket is still bound. A fixed
65,536-bit bitmap shared across the run rejects previously used source ports,
including ports from failed sessions and other resolver aliases. Thus repeated
identical questions
cannot accept an older attempt's reply merely because an ID was reused, even
after rotation, using socket tuples as seen by this host. Network devices that
rewrite/reuse those tuples are outside the transport's control. Failed attempts
to choose a fresh source port stop after 64
tries and return an error; the transport never silently relaxes this rule.

There are at most 1,024 active transport calls per endpoint, one live socket
(two briefly during rotation), a bounded pending map, an approximately 128KiB ID
pool; all transports share one 8KiB port-history bitmap. Retired ID pools are
released. The socket
requests a 4MiB receive buffer; the operating system may cap the actual size.
These limits are implementation bounds, not new CLI concurrency defaults.
The OS ephemeral-port range and ports used elsewhere on the host limit how many
rotations can succeed in an extremely long run. Source-port history is per run,
not persisted between invocations.

Writes serialize only the write deadline and datagram send. Waiting writers can
cancel without waiting for another query's timeout. Query deadlines never change
the shared socket's read deadline. Shutdown cancels waiters, closes sockets, and
joins receivers; the engine closes every resolver on all exit paths.

## TCP fallback

A validated truncated UDP reply triggers a separate TCP exchange using the
remaining attempt deadline. TCP fallback is bounded to 1,024 simultaneous calls
per resolver and remains subject to the engine's address concurrency. Queued
fallbacks and pending TCP reads respect cancellation. TCP must return a complete
response matching the ID, opcode, flags, and full question; an invalid or still
truncated response becomes a lookup error. TCP sockets remain per exchange.

## Validation

Transport tests cover source/ID/question/flag mismatches, malformed packets,
out-of-order replies, duplicate and late identical questions, deadline retirement,
ID exhaustion and cancellable backpressure, port rotation/exhaustion, receive
failure recovery, IPv6 resolver endpoints, and concurrent shutdown. Integration
tests cover TCP validation, fallback limits/cancellation, and engine cleanup.
Existing CLI and synthetic benchmark fixtures also run unchanged.

Use the [benchmark runner](../benchmarks/README.md) to compare this transport with
the committed baseline. Those measurements include initial socket/ID-pool setup
and local fixture/verifier overhead, and do not predict internet performance.
