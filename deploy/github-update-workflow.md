# GitHub update workflow contract

The managed repository owns `.github/workflows/vuelta-update.yml`, copied from
`vuelta-update.example.yml`. Both Vuelta references in that wrapper must use
the same reviewed full commit SHA.

Contract version 1 accepts only:

- `request_id`: a 22-character opaque Vuelta operation ID;
- `base_commit`: the exact 40-character lowercase commit from the successful
  server scan;
- `policy_version`: exactly `1`;
- `cooldown_days`: exactly `14`;
- `include_major`: `false` for routine updates and `true` only after explicit
  operator review.

The wrapper's dispatch ref is the configured protected branch. The reusable
workflow checks out `base_commit` directly, rediscovers candidates with the
pinned Vuelta engine, selects only direct stable delayed-latest changes, runs
the repository's security and verification gates, validates changed paths,
and pushes a review branch. It creates a pull request only after every gate
passes.

The workflow has contents and pull-request permissions only. It receives no
production SSH, Docker-host, GHCR deployment, Telegram, or application
credentials, and it contains no deployment step.
