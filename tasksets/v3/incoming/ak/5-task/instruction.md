# Hermetic CI Artifact Resolver and Promotion Planner

Implement `/app/engine.py`.

The resolver receives immutable artifact candidates, root requirements, a cache index, and a promotion policy. It must normalize POSIX paths without filesystem access; reject absolute paths, control characters, empty/`.`/`..` segments, encoded separators, Unicode normalization collisions, and case-fold collisions.

Resolve the highest compatible semantic-version assignment for the entire dependency graph. Requirements support exact versions, comma-separated comparator intersections, `^`, `~`, and prerelease ordering. One version per package is allowed. Detect cycles and unsatisfiable diamonds. Candidate selection is deterministic and must prefer, in order, a fully trusted graph, fewer cache misses, higher root versions, higher transitive versions, then canonical digest tuple.

Verify SHA-256 content digests, builder authorization, provenance subject binding, and that every dependency digest in provenance equals the selected artifact. Generate a stable topological build plan and an atomic promotion plan. Cache entries are usable only when all provenance checks still hold; a poisoned cache must not influence resolution.

Hidden tests contain downgrade traps, prerelease boundaries, Unicode/path aliases, cache poisoning, dependency-confusion candidates, cycles, and equal-version candidates with different provenance.
