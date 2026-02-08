use rackspace_email::{Alias, RackspaceClient};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let user_key = env::var("RACKSPACE_USER_KEY").expect("RACKSPACE_USER_KEY must be set").trim().to_string();
    let secret_key = env::var("RACKSPACE_SECRET_KEY").expect("RACKSPACE_SECRET_KEY must be set").trim().to_string();
    let customer_id = env::var("RACKSPACE_CUSTOMER_ID").ok().map(|s| s.trim().to_string());
    let domain = env::var("RACKSPACE_DOMAIN").expect("RACKSPACE_DOMAIN must be set").trim().to_string();

    let client = RackspaceClient::new(user_key, secret_key, customer_id, None)?;

    let args: Vec<String> = env::args().collect();
    // args[0] is binary name
    // args[1] is action
    // args[2] is alias name
    // args[3...] are emails

    if args.len() < 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let action = &args[1];
    let alias_name = &args[2];
    let emails = if args.len() > 3 {
        args[3..].to_vec()
    } else {
        Vec::new()
    };

    match action.as_str() {
        "create" => {
            if emails.is_empty() {
                eprintln!("Error: 'create' action requires at least one email address.");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            let alias = Alias {
                alias: alias_name.clone(),
                email_list: emails,
            };
            println!("Creating alias '{}' on domain '{}'...", alias_name, domain);
            match client.create_rackspace_alias(&domain, &alias).await {
                Ok(_) => println!("Successfully created alias: {} -> {:?}", alias.alias, alias.email_list),
                Err(e) => eprintln!("Failed to create alias: {}", e),
            }
        }
        "update" => {
            if emails.is_empty() {
                eprintln!("Error: 'update' action requires at least one email address.");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            let alias = Alias {
                alias: alias_name.clone(),
                email_list: emails,
            };
            println!("Updating alias '{}' on domain '{}'...", alias_name, domain);
            match client.update_rackspace_alias(&domain, &alias).await {
                Ok(_) => println!("Successfully updated alias: {} -> {:?}", alias.alias, alias.email_list),
                Err(e) => eprintln!("Failed to update alias: {}", e),
            }
        }
        "delete" => {
            println!("Deleting alias '{}' on domain '{}'...", alias_name, domain);
            match client.delete_rackspace_alias(&domain, alias_name).await {
                Ok(_) => println!("Successfully deleted alias '{}'.", alias_name),
                Err(e) => eprintln!("Failed to delete alias: {}", e),
            }
        }
        _ => {
            eprintln!("Invalid action: {}", action);
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} <create|update|delete> <alias_name> [email1 email2 ...]", program_name);
}