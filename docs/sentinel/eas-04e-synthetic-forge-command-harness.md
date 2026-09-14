# EAS-04E — Synthetic Forge_Command Adapter Harness

CP4E composes the existing CP4B admission/return contract, CP4C bounded local
collector, and CP4D deterministic observation pipeline in one test-only,
dependency-injected compatibility harness.

The harness accepts only an explicit synthetic mission, caller-supplied absolute
fixture root, manifest, rules, clock, stop state, and revision state. It performs
no endpoint discovery, network access, scheduling, credential handling,
persistence, repository mutation, Registry/DataForge write, remediation, or
live Forge_Command interaction. The harness itself creates no files and reports
zero accepted effects.

Invalid, stale, substituted, collided, or replayed admissions are rejected before
collection. Revision drift and control failures stop collection. Failed or
partial collection, missing evidence, verifier unavailability, and disagreement
remain visible and cannot produce a healthy return. Accepted returns preserve
mission, authority, target SHA/tree, procedure, coverage, and usage identities
and are bound by the existing canonical return hash.

This module is not exported by the public package entry point and does not create
a runtime activation path.
