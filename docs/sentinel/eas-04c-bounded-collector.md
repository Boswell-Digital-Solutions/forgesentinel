# EAS-04C Bounded Local Collector

The CP4C collector is an internal library function, not a runtime entry point. It consumes an already validated CP4B admission, one absolute local root, an explicit path manifest, and injected time/control/revision functions.

It permits safe UTF-8 text beneath `doc/system/`, `docs/sentinel/`, `src/`, `test/`, and `fixtures/` only. It rejects absolute/traversal paths, symlinks, non-files, root escape, malformed UTF-8, NUL-bearing binary content, secret-shaped content, file replacement during a read, stale authority, stop/revocation/channel loss, revision drift, duplicate paths, and cap overshoot.

The collector does not invoke Git, scripts, subprocesses, package managers, network clients, Forge_Command, Registry, or DataForge. It writes nothing to the target and returns `acceptedEffects: 0`. Analyzer/verifier wiring remains outside CP4C.
