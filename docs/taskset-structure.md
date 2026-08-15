# Taskset Structure and Repository Rules

Cyber-Bench keeps multiple benchmark releases in one Git repository so they can
share documentation, source artifacts, agent guidance, and Git history without
mixing their task packages.

The repository uses a taskset boundary:

```text
Cyber-Bench/
├── AGENTS.md
├── README.md
├── docs/                       # Shared documentation
├── bundles/                    # Bundle metadata and manifests
├── harbor/                     # Legacy Harbor task sources and assets
├── tasksets/
│   ├── v1/
│   │   └── tasks/              # Established V1 packages
│   ├── v2/
│   │   └── tasks/              # Curated 100-task headroom set
│   └── v3/
│       └── tasks/              # Remaining and V3-only packages
├── jobs/
│   ├── v1/                     # Ignored V1 run output
│   ├── v2/                     # Ignored V2 run output
│   └── v3/                     # Ignored V3 run output
└── memories/                   # Local design and experiment notes
```

There is intentionally no root `tasks/` compatibility path. Every command,
test, and document should name the intended taskset explicitly.

## Ownership Rules

1. A task package belongs to exactly one versioned root:
   `tasksets/<version>/tasks/`.
2. V2 and V3 are a partition: a task package name belongs to only one of those
   releases. V1 remains an independent benchmark snapshot and may contain
   related challenges.
3. Repository-level docs, manifests, and source artifacts may live at the root.
   Challenge assets, graders, solutions, instructions, and task metadata stay
   inside their task package.
4. Do not make opportunistic content changes while moving task packages between
   organizational paths. Structural moves and task-content edits must be
   separately reviewable.
5. Run output goes under `jobs/<version>/` so results from different tasksets
   cannot be mistaken for one another.

## V1

V1 lives at `tasksets/v1/tasks/`. It contains 35 flat, self-contained packages:
Web-5 combined and individual hint-level tasks plus five memory-vulnerability
tasks. Existing V1 regression tests use this path.

Run the full V1 set:

```bash
harbor run \
  --path tasksets/v1/tasks \
  --agent oracle \
  --force-build \
  --job-name v1_all_tasks_oracle \
  --jobs-dir jobs/v1
```

## V2

V2 lives at `tasksets/v2/tasks/` and contains the 100 package snapshots selected
in the current `tasks_29_July/tasks` bundle. Bundle ranking prefixes are not
part of the repository task directory names.

Run the V2 set:

```bash
harbor run \
  --path tasksets/v2/tasks \
  --agent oracle \
  --force-build \
  --job-name v2_all_tasks_oracle \
  --jobs-dir jobs/v2
```

## V3

V3 lives at `tasksets/v3/tasks/` and contains the 19 packages not selected for
V2, including the pre-existing V3-only tasks. No task name appears in both V2
and V3.

Run the V3 set:

```bash
harbor run \
  --path tasksets/v3/tasks \
  --agent oracle \
  --force-build \
  --job-name v3_all_tasks_oracle \
  --jobs-dir jobs/v3
```

## Package Contract

A runnable package normally contains:

```text
<task>/
├── instruction.md
├── task.toml
├── environment/
├── solution/
└── tests/
```

Before adding a package to a taskset, validate its required files, Docker
Compose configuration, solution, and verifier. Run static checks before an
oracle run, and run an oracle before a paid model calibration. Use cheaper
models unless a costlier model is explicitly requested.

## Adding Another Taskset

Create `tasksets/<new-version>/tasks/`, document its scope in the root README,
make all commands reference the new root explicitly, and write outputs to
`jobs/<new-version>/`. Do not copy task packages between releases as part of the
new release setup unless that duplication is intentional and reviewable.
