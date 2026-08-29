# router-infra

Shared development and release infrastructure for the router repositories.

This repository provides reusable CI actions and workflows, release policy,
signing integration, SBOM generation, and provenance conventions. Repository-
specific CI remains beside the code it validates; consumers opt into shared
workflows by pinned revision.

No firmware, package recipe, device definition, or private signing material is
stored here.
