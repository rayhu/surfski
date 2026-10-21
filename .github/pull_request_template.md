## Summary

<!-- What changed and why. Link the issue. -->

## Testing

<!-- What you ran (`uv run pytest -q`, manual checks) and what the new tests cover. -->

## Technical decisions

<!-- Options considered, pros and cons, and the one implemented. -->

## Security

<!-- Owner isolation, secrets/PII in logs or audit rows, new network paths, defaults (write features stay opt-in). Write "None" if not applicable. -->

## Checklist

- [ ] Tests added or updated; `uv run pytest -q` passes (no calls to Google)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] `README.md` updated if behavior or configuration changed
- [ ] New per-user tables use an `owner` column (see CONTRIBUTING.md)

Closes #
