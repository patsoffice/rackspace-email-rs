# Rackspace Email API Client

A Rust library for interacting with the Rackspace Email API. This library implements domain read operations, full alias management (CRUD), and mailbox management (CRUD).

## Features

* **Authentication**: Secure `X-Api-Signature` header generation.
* **Domains**: List all domains and retrieve specific domain details.
* **Aliases**: List, create, read, update, and delete Rackspace email aliases.
* **Mailboxes**: List, create, read, update, and delete Rackspace mailboxes (email accounts).
* **Pagination**: Automatic pagination for list operations.
* **Throttling**: Automatic retries with exponential backoff for rate-limited requests (configurable).
* **Input Validation**: Path segment validation on all public methods to reject empty or malformed identifiers.
* **Structured Errors**: `ApiError` enum with typed variants including HTTP status codes for programmatic error handling.

**Note:** Customer listing and mailbox management (CRUD) are currently untested against the live API.

## Installation

Add the library to your `Cargo.toml`.

```toml
[dependencies]
rackspace-email = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

## Configuration

The client requires your Rackspace Email API credentials (User Key and Secret Key). The Customer ID is optional.

To run the included binaries, set the following environment variables:

```bash
export RACKSPACE_USER_KEY="your_user_key"
export RACKSPACE_SECRET_KEY="your_secret_key"
# export RACKSPACE_CUSTOMER_ID="your_customer_id" # Optional
# export RACKSPACE_DOMAIN="example.com" # Optional: Specify a domain to inspect.
# export RUST_LOG=debug # Optional: Set the log level.
```

## CLI Tools

Ensure you have set the environment variables described in the [Configuration](#configuration) section.

### Debugging Tool

A simple tool to list domains, aliases, and mailboxes to verify connectivity and permissions.

```bash
cargo run --bin debugging
```

### Alias Operations

A CLI tool to create, update, and delete aliases. **Note:** The `RACKSPACE_DOMAIN` environment variable is required for this tool.

```bash
cargo run --bin alias-ops -- create <alias_name> <email1> [email2 ...]
cargo run --bin alias-ops -- update <alias_name> <email1> [email2 ...]
cargo run --bin alias-ops -- delete <alias_name>
```

## Usage Example

```rust
use rackspace_email::{RackspaceClient, Alias, ApiError, Mailbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the client (returns Result)
    let mut client = RackspaceClient::new(
        "YOUR_USER_KEY".to_string(),
        "YOUR_SECRET_KEY".to_string(),
        None, // Customer ID (Optional)
        None, // Optional User-Agent override
    )?
    .with_max_retries(5); // Optional: Configure retries for throttling (default is 3)

    // Discover and set customer ID (for reseller accounts)
    let customer_id = client.find_customer_id().await?;
    client.set_customer_id(customer_id);

    // List Domains
    let domains = client.list_domains(None).await?;
    for domain in domains {
        println!("Found domain: {}", domain.name);
    }

    // Create a new Alias
    let new_alias = Alias {
        alias: "team".to_string(),
        email_list: vec!["alice@example.com".to_string(), "bob@example.com".to_string()],
    };

    client.create_rackspace_alias("example.com", &new_alias).await?;

    // Create a new Mailbox
    let new_mailbox = Mailbox {
        name: "user1".to_string(),
        password: Some("Secret123!".to_string()),
        size: Some(1024),
        enabled: Some(true),
    };

    client.create_rackspace_mailbox("example.com", &new_mailbox).await?;

    Ok(())
}
```

## Error Handling

`ApiError` provides structured variants for programmatic error handling:

```rust
use rackspace_email::ApiError;

match result {
    Err(ApiError::Http { status, body }) => {
        // HTTP error with status code (e.g., 403, 404, 500)
        eprintln!("HTTP {}: {}", status, body);
    }
    Err(ApiError::Validation(msg)) => {
        // Invalid input (empty domain, path separators in identifiers, etc.)
        eprintln!("Invalid input: {}", msg);
    }
    Err(ApiError::Api(msg)) => {
        // API-level errors (e.g., no customers found)
        eprintln!("API error: {}", msg);
    }
    Err(e) => {
        // Network, serialization errors
        eprintln!("Error: {}", e);
    }
    Ok(value) => { /* success */ }
}
```

## License

This project is licensed under the [MIT License](LICENSE).
