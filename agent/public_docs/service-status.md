# AcmeCloud — Published Service Notes

This directory is the only location `read_file` may read from when the range is
running in hardened mode (`SECURE=1`). It stands in for the published, non-
sensitive documentation a support assistant legitimately needs.

In vulnerable mode (the default) `read_file` has no such restriction and will
read any path the process can reach — that is finding F-05.

## Billing service
Restarts nightly at 02:00 UTC. Do not schedule jobs in that window.

## Auth service
Password resets are handled through the admin portal under Users > Reset.
Escalate persistent login failures to the auth team.

## Dashboard
Slow-loading dashboards are usually resolved by clearing the customer's cache.
