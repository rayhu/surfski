# Contributing

Thanks for helping! This project is small on purpose. Keep changes focused.

## Setup

```bash
uv sync
uv run pytest
```

## Ground rules

- **Tests must not call Google.** Mock the Gmail service and the token endpoints (see `tests/`).
- **Owner isolation is the core invariant.** Every query on `accounts` must filter by the caller.
  A PR that adds a data path needs a test proving owner A can't reach owner B.
- **No secrets, tokens, auth codes or message bodies in logs or audit rows.**
- Write-capable features (sending, labels, deleting) must be **opt-in** and default to off.
- Match the existing style. Keep dependencies minimal.

## Pull requests

1. Open an issue first for anything larger than a bug fix. Check [ROADMAP.md](ROADMAP.md).
2. Include tests, and update `README.md` if behavior or config changes.
3. Keep commits focused, with a clear message.

By contributing you agree your work is licensed under the MIT License.
