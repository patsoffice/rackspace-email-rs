use chrono::Utc;
use rackspace_email::RackspaceClient;
use rand::seq::SliceRandom;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let user_key = env::var("RACKSPACE_USER_KEY")
        .expect("RACKSPACE_USER_KEY must be set")
        .trim()
        .to_string();
    let secret_key = env::var("RACKSPACE_SECRET_KEY")
        .expect("RACKSPACE_SECRET_KEY must be set")
        .trim()
        .to_string();
    let customer_id = env::var("RACKSPACE_CUSTOMER_ID")
        .ok()
        .map(|s| s.trim().to_string());
    let target_domain = env::var("RACKSPACE_DOMAIN")
        .ok()
        .map(|s| s.trim().to_string());

    println!("Timestamp: {}", Utc::now().format("%Y%m%d%H%M%S"));

    let client = RackspaceClient::new(user_key, secret_key, customer_id.clone(), None)?;

    println!("Listing domains...");
    let domains = client.list_domains(None).await?;
    println!("Found {} domains.", domains.len());

    for domain in &domains {
        println!(
            "- {} (Service Type: {:?})",
            domain.name, domain.service_type
        );
    }

    let selected_domain_name = if let Some(d) = target_domain {
        Some(d)
    } else {
        domains
            .choose(&mut rand::thread_rng())
            .map(|d| d.name.clone())
    };

    if let Some(domain_name) = selected_domain_name {
        println!("\nListing aliases for domain: {}", domain_name);

        match client.list_rackspace_aliases(&domain_name, None).await {
            Ok(aliases) => {
                println!("Fetched {} aliases", aliases.len());
                for alias in aliases {
                    println!("  - {} -> {:?}", alias.alias, alias.email_list);
                }
            }
            Err(e) => eprintln!("Error listing aliases: {}", e),
        }

        println!("\nListing mailboxes for domain: {}", domain_name);
        match client.list_rackspace_mailboxes(&domain_name, None).await {
            Ok(mailboxes) => {
                println!("Found {} mailboxes.", mailboxes.len());
                for mailbox in mailboxes {
                    println!(
                        "  - {} (Enabled: {:?}, Size: {:?})",
                        mailbox.name, mailbox.enabled, mailbox.size
                    );
                }
            }
            Err(e) => {
                eprintln!("Error listing mailboxes: {}", e);
            }
        }
    } else {
        println!("No domains found, skipping detail listing.");
    }

    Ok(())
}
