---
name: Feature request
about: Propose a scoped improvement to WARDEN
title: ''
labels: enhancement
assignees: ''
---

## Problem or limitation

What existing behaviour is insufficient? Cite the relevant source, test, or
documented limitation where possible.

## Proposed change

Describe the smallest change that would address the problem. Do not propose a
second configuration engine or duplicate subsystem.

## Evidence and scope

- Affected components (Rust userspace, eBPF, config, CLI, installer, docs):
- Expected observable result:
- Kernel / distribution assumptions:
- New privileges, hooks, or runtime dependencies:
- Tests or measurements needed to support the change:

## Alternatives considered

Why is this preferable to changing configuration, documentation, or an existing
subsystem?

## Safety boundary

Explain whether the change could affect enforcement, misleading success states,
event fidelity, or host stability. State any testing that cannot be performed in
ordinary unprivileged CI.

> Do not include credentials, customer data, private hostnames/IPs, or
> unredacted host logs. Suspected vulnerabilities belong in the private
> reporting channel, not in a public feature request.
