# Use case

## Problem

Claude Cowork fulfils a user request by invoking tools, MCP connectors, skills,
and plugins on the user's behalf, often against local files and company data.
Organisations running Cowork at scale need to answer a governance question:

> For the tools and MCP connectors Cowork invoked, do we have central, retained
> visibility, and can we tell when it called a component with a known CVE?

Cowork can stream rich telemetry over OpenTelemetry, but that telemetry names the
component without a version, is opt-in, and carries no native mapping to a
known-CVE inventory. The result is four distinct gaps: telemetry may not be
flowing, invoked components may not be identifiable and versioned, there may be no
CVE-aware detection, and the only preventive lever (an org-wide connector toggle)
is coarse.

## Who it is for

Security engineering and platform teams who own an organisation's Cowork
configuration and its SIEM. Secondary users: auditors and incident responders who
need to reconstruct what Cowork did and whether a called component was known to be
vulnerable.

## What coverguard does

Given exported Cowork OTel events, a pinned component inventory, and a CVE feed,
coverguard runs a set of detection rules and produces a coverage report that maps
measured results to the four gaps, plus machine-readable alerts for a SIEM.

## Scope

In scope: parsing Cowork OTel events, matching invoked components to an inventory
and a CVE feed, detection rules, and a coverage report.

Out of scope: preventing an invocation (the platform's org-wide toggle is the only
native prevention), managing the inventory's contents, and being a general SIEM.

## Non-goals

- Not a preventive control. It is detective and reports after the fact.
- Not a source of record. Its output is a derived view, not an audit store.
- Not a network service. It is a local CLI or CI job.

## Success criteria

For any set of events, the operator can answer: who called what, when, whether it
was approved, and whether the called component was known to be vulnerable, and can
be alerted on the last of these. Coverage is reported honestly, including the
telemetry-silence and below-minimum-version cases, so absence of alerts is never
mistaken for safety.
