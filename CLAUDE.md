# Rackspace Email API Client (Rust)

Async Rust client library and CLI tools for the Rackspace Email REST API. Manages domains, aliases, and mailboxes for Rackspace Email accounts.

## Commands

```bash
# Build
cargo build --verbose

# Test (all)
cargo test --verbose

# Test (single)
cargo test <test_name> -- --nocapture

# Lint (CI enforces -D warnings)
cargo clippy --all-features --all-targets

# Run this if there are clippy warnings before you fix them yourself
cargo clippy --all-features --all-targets --allow-dirty --fix

# Format check (CI enforces this)
cargo fmt --check

# Format fix
cargo fmt

# Run CLI tools
RUST_LOG=debug cargo run --bin debugging
RUST_LOG=debug cargo run --bin alias-ops -- <create|update|delete> <alias_name> [emails...]
```

## Environment Variables

- `RACKSPACE_USER_KEY` - API user key (required)
- `RACKSPACE_SECRET_KEY` - API secret key (required)
- `RACKSPACE_CUSTOMER_ID` - Account number (optional, for resellers)
- `RACKSPACE_DOMAIN` - Target domain (required for alias-ops, optional for debugging)
- `RUST_LOG` - Log level (e.g., `debug`)

## Architecture

Single crate with a library and two binaries:

- `src/lib.rs` - All library code: API client, types, auth, pagination, retries, tests
- `src/debugging.rs` - Diagnostic CLI: lists domains, aliases, mailboxes
- `src/alias_ops.rs` - Alias management CLI: create/update/delete aliases

### Key Internal Patterns

- `RackspaceClient` is the main entry point. All API calls go through a single generic `request<T, B, Q>()` method that handles auth, serialization, and retries.
- Pagination is transparent: `list_*` methods loop internally and return complete `Vec<T>`.
- Throttling: 403 + "Exceeded request limits" body triggers exponential backoff retries (2^attempt seconds, default max 3).
- Auth signature: `SHA1(user_key + user_agent + timestamp + secret_key)`, base64-encoded, sent as `X-Api-Signature` header. Regenerated per retry.
- Multi-member alias detail fetch: `list_rackspace_aliases` fetches full details for aliases with `number_of_members > 1`.

## Code Style

- Public API methods accept `&str`, not `String`. Callers decide whether to allocate.
- Error types use `thiserror` derive macros, never manual `Display` impls
- All public client methods return `Result<T, ApiError>`
- Builder pattern: `with_base_url()`, `with_clock()`, `with_max_retries()` for chainable config
- Serde: use `#[serde(rename = "...")]` for camelCase API fields, `#[serde(alias = "...")]` for flexible deser, `#[serde(skip_serializing_if = "Option::is_none")]` for optional fields
- No CLI framework — raw `env::args()` parsing in binaries
- Binaries call `env_logger::init()`. The library never initializes logging.
- `validate_path_segment()` must be called on all user-provided path components before building URLs
- Aliases use form-encoded bodies (`as_form: true`), mailboxes use JSON bodies

## Gotchas

- The API returns alias members differently depending on count: single-member aliases use `singleMemberName`, multi-member use `emailAddressList.emailAddress[]`. The `AliasResponse -> Alias` conversion in `From` handles this.
- Empty response bodies are normalized to `"null"` for serde deserialization (see `request()` method).
- The `size` field in API pagination responses maps to `limit` in `PagedResponse` (via `#[serde(rename = "size")]`).
- Mailbox list responses use `rsMailboxes` as the JSON key (not `mailboxes`).

### Commit Style

- Prefix: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`
- Summary line under 80 chars with counts where relevant
- Body: each logical change on its own `-` bullet
- Summarize what was added/changed and why, not just file names

## CI

GitHub Actions runs on push/PR to main: build, test, fmt check, clippy with `-D warnings`. All four must pass.
