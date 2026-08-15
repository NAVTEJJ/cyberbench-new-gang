# Authorization operations guide

Meridian authorization policy is a directed graph. The baseline graph has an
integer version; every edge has a unique ID, endpoints, an active state, and a
flag recording whether the edge delegates authority.

Policy writers stage idempotent edge activations and revocations under a
transaction ID. Staging does not alter authorization. A later commit atomically
applies all earlier staged operations bearing its transaction ID and creates
the commit's policy version, then consumes that staged transaction. A commit is
invalid when its transaction is unknown or its version is not greater than the
current version. Uncommitted work has no effect. Preserve each valid committed
version as a snapshot.

Protected operations record the exact `authz_version` used for their decision.
That version identifies the committed snapshot consulted by the service. A
delegated route is a directed active path that contains at least one edge
marked `delegated`.
