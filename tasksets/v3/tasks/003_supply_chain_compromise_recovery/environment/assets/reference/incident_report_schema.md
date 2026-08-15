# Incident report schema

Write the investigation result to `/app/incident_report.json` as one JSON object.

Required fields:

- `verdict`: `compromised` or `clean`;
- `artifact`: `{name, version, artifact_sha256, attestation_id}`;
- `source_baseline`: `{revision, path, source_sha256, reproduced_artifact_sha256, reproducible_match}`;
- `generated_intermediate`: `{clean_path, clean_sha256, composed_path, composed_sha256, selector, offset}`;
- `entry_path`: ordered dependency names from the affected component to the artifact;
- `activation`: `{build_mode, component, stage, extension_target}`;
- `behavior`: `{declared_profile, observed_profile, capabilities, sink}`;
- `injection_event`: the event identifier that best identifies the unauthorized build input;
- `causal_chain`: ordered, non-empty list of event identifiers from source checkout through the observed policy violation;
- `candidate_assessments`: one object for every candidate in
  `evidence/integrity_findings.jsonl`, each containing `{candidate_id, subject,
  disposition, promoted, selected, reachable_from_affected_component,
  activated_in_observed_event, evidence_ids}`. Valid dispositions are `causal`,
  `unrelated-component`, `not-selected`, `discarded`, and
  `recipe-reproducible`;
- `evidence`: non-empty list of `{sources, identifiers, finding}` objects;
- `summary`: non-empty string.

Each evidence source must name an existing path under `/app`. Identifiers must occur in at least one cited source. Findings should state what the cited records prove rather than merely restating field values.
Paths in `source_baseline.path`, `generated_intermediate.clean_path`, and
`generated_intermediate.composed_path` may be relative to `/app` or absolute
under `/app`; both forms have the same meaning.

For a candidate assessment, `selected` means that the candidate's exact package
version or artifact is selected anywhere in the captured monorepo lock state. It
does not mean selected by, or reachable from, the affected component; report that
separately in `reachable_from_affected_component`.

Candidate evidence identifiers must occur in the supplied offline evidence and
collectively substantiate the disposition and boolean fields. Cite evidence for
the candidate flag and the relevant lifecycle stages: build input and mutation,
promotion, resolution or lock selection, and observed activation for a causal
candidate; build input, promotion, and global lock selection for an unrelated
selected package; promotion for a promoted but unselected package; workspace
input and discard for a discarded candidate; and checkout and package emission
for a recipe-reproducible candidate. The grader checks these semantic evidence
categories, not one fixed list of event identifiers.
