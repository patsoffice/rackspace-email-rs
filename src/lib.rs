use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use log::debug;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::fmt::Debug;
use thiserror::Error;

/// Errors that can occur when interacting with the Rackspace Email API.
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("API returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("API error: {0}")]
    Api(String),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Form serialization error: {0}")]
    Form(#[from] serde_urlencoded::ser::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Represents a customer account.
#[derive(Debug, Serialize, Deserialize)]
pub struct Customer {
    pub name: String,
    #[serde(rename = "accountNumber")]
    pub account_number: String,
}

/// A generic response wrapper for paged results.
#[derive(Debug, Deserialize)]
pub struct PagedResponse<T> {
    pub total: usize,
    pub offset: usize,
    #[serde(rename = "size")]
    pub limit: usize,
    #[serde(flatten)]
    pub items: T,
}

#[derive(Debug, Deserialize)]
struct CustomerList {
    customers: Vec<Customer>,
}

/// Represents a domain in the Rackspace Email system.
#[derive(Debug, Serialize, Deserialize)]
pub struct Domain {
    pub name: String,
    #[serde(rename = "serviceType")]
    pub service_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DomainList {
    domains: Vec<Domain>,
}

/// Represents an email alias.
#[derive(Debug, Serialize, Deserialize)]
pub struct Alias {
    #[serde(alias = "name")]
    pub alias: String,
    #[serde(rename = "emailList", default)]
    pub email_list: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AliasRequest {
    #[serde(rename = "aliasEmails")]
    alias_emails: String,
}

#[derive(Debug, Deserialize)]
struct EmailAddressListWrapper {
    #[serde(rename = "emailAddress")]
    email_address: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AliasResponse {
    #[serde(alias = "name")]
    alias: String,
    #[serde(rename = "emailList", default)]
    email_list: Vec<String>,
    #[serde(rename = "singleMemberName")]
    single_member_name: Option<String>,
    #[serde(rename = "numberOfMembers", default)]
    number_of_members: usize,
    #[serde(rename = "emailAddressList")]
    email_address_list: Option<EmailAddressListWrapper>,
}

impl From<AliasResponse> for Alias {
    fn from(resp: AliasResponse) -> Self {
        let mut email_list = resp.email_list;
        if let Some(wrapper) = resp.email_address_list {
            email_list.extend(wrapper.email_address);
        }
        if email_list.is_empty() {
            if let Some(single) = resp.single_member_name {
                email_list.push(single);
            }
        }
        Alias {
            alias: resp.alias,
            email_list,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AliasList {
    aliases: Vec<AliasResponse>,
}

/// Represents a mailbox (email account).
#[derive(Debug, Serialize, Deserialize)]
pub struct Mailbox {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct MailboxList {
    #[serde(rename = "rsMailboxes")]
    mailboxes: Vec<Mailbox>,
}

#[derive(Serialize)]
struct PageParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
}

/// Trait for abstracting time, primarily used for testing signature generation.
pub trait Clock: Debug + Send + Sync {
    fn timestamp(&self) -> String;
}

#[derive(Debug)]
struct SystemClock;

impl Clock for SystemClock {
    fn timestamp(&self) -> String {
        Utc::now().format("%Y%m%d%H%M%S").to_string()
    }
}

fn validate_path_segment(value: &str, name: &str) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(ApiError::Validation(format!("{} cannot be empty", name)));
    }
    if value.contains('/') || value.contains('\\') || value.contains('\0') {
        return Err(ApiError::Validation(format!(
            "{} cannot contain '/', '\\', or null bytes",
            name
        )));
    }
    Ok(())
}

/// Client for the Rackspace Email API.
pub struct RackspaceClient {
    client: Client,
    base_url: String,
    user_key: String,
    secret_key: String,
    user_agent: String,
    customer_id: Option<String>,
    clock: Box<dyn Clock>,
    max_retries: u32,
}

impl RackspaceClient {
    /// Creates a new Rackspace Email API Client.
    ///
    /// # Arguments
    ///
    /// * `user_key` - The API User Key.
    /// * `secret_key` - The API Secret Key.
    /// * `customer_id` - Optional Customer ID (Account Number). Required for resellers, usually `None` for direct customers.
    /// * `user_agent` - Optional custom User-Agent string.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        user_key: &str,
        secret_key: &str,
        customer_id: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Self, ApiError> {
        let ua_string = user_agent
            .unwrap_or("RustRackspaceClient/0.2")
            .to_string();
        let client = Client::builder().user_agent(&ua_string).build()?;

        Ok(Self {
            client,
            base_url: "https://api.emailsrvr.com/v1".to_string(),
            user_key: user_key.to_string(),
            secret_key: secret_key.to_string(),
            user_agent: ua_string,
            customer_id: customer_id.map(str::to_string),
            clock: Box::new(SystemClock),
            max_retries: 3,
        })
    }

    /// Sets a custom base URL for the client. Useful for testing.
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.to_string();
        self
    }

    /// Sets a custom clock for the client. Useful for testing deterministic signatures.
    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets the maximum number of retries for throttled requests. Default is 3.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the customer ID (account number) on the client.
    pub fn set_customer_id(&mut self, id: &str) {
        self.customer_id = Some(id.to_string());
    }

    fn generate_signature(&self) -> String {
        let timestamp = self.clock.timestamp();

        let mut hasher = Sha1::new();
        hasher.update(self.user_key.as_bytes());
        hasher.update(self.user_agent.as_bytes());
        hasher.update(timestamp.as_bytes());
        hasher.update(self.secret_key.as_bytes());
        let hash = hasher.finalize();

        let signature = general_purpose::STANDARD.encode(hash);

        format!("{}:{}:{}", self.user_key, timestamp, signature)
    }

    fn customer_path(&self, subpath: &str) -> Result<String, ApiError> {
        if let Some(id) = &self.customer_id {
            validate_path_segment(id, "customer_id")?;
            Ok(format!("/customers/{}{}", id, subpath))
        } else {
            Ok(subpath.to_string())
        }
    }

    /// Sends an HTTP request to the API.
    ///
    /// Handles authentication signature generation and JSON serialization/deserialization.
    ///
    /// # Throttling
    ///
    /// If a user is over the throttling limit then a 403 HTTP code will be returned with an "Exceeded request limits" message.
    /// This method implements a retry mechanism with exponential backoff for this specific error.
    async fn request<T, B, Q>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        query: Option<&Q>,
        as_form: bool,
    ) -> Result<T, ApiError>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
        Q: Serialize + ?Sized,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut attempt = 0u32;
        let max_retries = self.max_retries;

        loop {
            attempt += 1;
            // Regenerate signature each attempt since it includes the current timestamp
            let signature = self.generate_signature();

            let mut req = self
                .client
                .request(method.clone(), &url)
                .header("User-Agent", &self.user_agent)
                .header("X-Api-Signature", signature)
                .header("Accept", "application/json");

            if let Some(q) = query {
                req = req.query(q);
            }

            if let Some(b) = body {
                if as_form {
                    if let Ok(form_body) = serde_urlencoded::to_string(b) {
                        debug!("Request Body: {}", form_body);
                    }
                    req = req.form(b);
                } else {
                    if let Ok(json_body) = serde_json::to_string(b) {
                        debug!("Request Body: {}", json_body);
                    }
                    req = req.json(b);
                }
            }

            let request = req.build()?;
            debug!("Request Method: {}", request.method());
            if let Some(q) = request.url().query() {
                debug!("Request Query: {}", q);
            }
            debug!("Request Headers for {}", request.url());
            for (key, value) in request.headers() {
                debug!("  {}: {:?}", key, value);
            }

            let resp = self.client.execute(request).await?;

            if resp.status().is_success() {
                let text = resp.text().await?;
                debug!("Response Body: {}", text);
                let json_text = if text.is_empty() { "null" } else { &text };
                let data = serde_json::from_str(json_text)?;
                return Ok(data);
            }

            let status = resp.status();
            let text = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
            debug!("Error Response Body: {}", text);

            // Check for throttling (collapsed conditional)
            if status == reqwest::StatusCode::FORBIDDEN
                && text.contains("Exceeded request limits")
                && attempt <= max_retries
            {
                debug!(
                    "Throttling detected. Retrying attempt {}/{}...",
                    attempt, max_retries
                );
                tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
                continue;
            }

            return Err(ApiError::Http {
                status: status.as_u16(),
                body: text,
            });
        }
    }

    /// Lists all customers associated with the API credentials.
    ///
    /// This is typically used to discover the Customer ID (Account Number).
    pub async fn list_customers(&self) -> Result<Vec<Customer>, ApiError> {
        let resp: CustomerList = self
            .request::<CustomerList, (), ()>(Method::GET, "/customers", None, None, false)
            .await?;
        Ok(resp.customers)
    }

    /// Finds the first customer associated with the credentials and returns the Customer ID.
    ///
    /// Use `set_customer_id` to apply the returned value to the client.
    pub async fn find_customer_id(&self) -> Result<String, ApiError> {
        let customers = self.list_customers().await?;
        if let Some(c) = customers.first() {
            Ok(c.account_number.clone())
        } else {
            Err(ApiError::Api(
                "No customers found for this user key".to_string(),
            ))
        }
    }

    /// Lists domains associated with the account.
    ///
    /// Automatically handles pagination to retrieve all domains.
    pub async fn list_domains(&self, page_size: Option<usize>) -> Result<Vec<Domain>, ApiError> {
        let mut domains = Vec::new();
        let mut offset = 0;
        let limit = page_size.unwrap_or(50);

        loop {
            let params = PageParams {
                offset: Some(offset),
                limit: Some(limit),
            };
            let path = self.customer_path("/domains")?;
            let resp: PagedResponse<DomainList> = self
                .request::<PagedResponse<DomainList>, (), PageParams>(
                    Method::GET,
                    &path,
                    None,
                    Some(&params),
                    false,
                )
                .await?;

            let batch_size = resp.items.domains.len();
            domains.extend(resp.items.domains);

            if batch_size < limit || domains.len() >= resp.total {
                break;
            }
            offset += batch_size;
        }
        Ok(domains)
    }

    /// Retrieves details for a specific domain.
    pub async fn get_domain(&self, domain: &str) -> Result<Domain, ApiError> {
        validate_path_segment(domain, "domain")?;
        let path = self.customer_path(&format!("/domains/{}", domain))?;
        self.request::<Domain, (), ()>(Method::GET, &path, None, None, false)
            .await
    }

    /// Lists Rackspace Email aliases for a specific domain.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    ///
    /// Automatically handles pagination to retrieve all aliases.
    pub async fn list_rackspace_aliases(
        &self,
        domain: &str,
        page_size: Option<usize>,
    ) -> Result<Vec<Alias>, ApiError> {
        validate_path_segment(domain, "domain")?;
        let mut all_aliases = Vec::new();
        let mut offset = 0;
        let limit = page_size.unwrap_or(50);

        loop {
            let params = PageParams {
                offset: Some(offset),
                limit: Some(limit),
            };
            let path = self.customer_path(&format!("/domains/{}/rs/aliases", domain))?;
            let resp: PagedResponse<AliasList> = self
                .request::<PagedResponse<AliasList>, (), PageParams>(
                    Method::GET,
                    &path,
                    None,
                    Some(&params),
                    false,
                )
                .await?;

            let batch_size = resp.items.aliases.len();
            for item in resp.items.aliases {
                if item.number_of_members > 1 {
                    let detailed = self.get_rackspace_alias(domain, &item.alias).await?;
                    all_aliases.push(detailed);
                } else {
                    all_aliases.push(Alias::from(item));
                }
            }

            if batch_size < limit || all_aliases.len() >= resp.total {
                break;
            }
            offset += batch_size;
        }
        Ok(all_aliases)
    }

    /// Retrieves details for a specific Rackspace Email alias.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn get_rackspace_alias(&self, domain: &str, alias: &str) -> Result<Alias, ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(alias, "alias")?;
        let path = self.customer_path(&format!("/domains/{}/rs/aliases/{}", domain, alias))?;
        let resp = self
            .request::<AliasResponse, (), ()>(Method::GET, &path, None, None, false)
            .await?;
        Ok(Alias::from(resp))
    }

    /// Creates a new Rackspace Email alias.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn create_rackspace_alias(
        &self,
        domain: &str,
        alias: &Alias,
    ) -> Result<(), ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(&alias.alias, "alias")?;
        let path =
            self.customer_path(&format!("/domains/{}/rs/aliases/{}", domain, alias.alias))?;
        let body = AliasRequest {
            alias_emails: alias.email_list.join(", "),
        };
        self.request::<(), AliasRequest, ()>(Method::POST, &path, Some(&body), None, true)
            .await?;
        Ok(())
    }

    /// Updates an existing Rackspace Email alias.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn update_rackspace_alias(
        &self,
        domain: &str,
        alias: &Alias,
    ) -> Result<(), ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(&alias.alias, "alias")?;
        let path =
            self.customer_path(&format!("/domains/{}/rs/aliases/{}", domain, alias.alias))?;
        let body = AliasRequest {
            alias_emails: alias.email_list.join(", "),
        };
        self.request::<(), AliasRequest, ()>(Method::PUT, &path, Some(&body), None, true)
            .await?;
        Ok(())
    }

    /// Deletes a Rackspace Email alias.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn delete_rackspace_alias(&self, domain: &str, alias: &str) -> Result<(), ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(alias, "alias")?;
        let path = self.customer_path(&format!("/domains/{}/rs/aliases/{}", domain, alias))?;
        self.request::<(), (), ()>(Method::DELETE, &path, None, None, false)
            .await
    }

    /// Lists Rackspace Email mailboxes for a specific domain.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    ///
    /// Automatically handles pagination to retrieve all mailboxes.
    pub async fn list_rackspace_mailboxes(
        &self,
        domain: &str,
        page_size: Option<usize>,
    ) -> Result<Vec<Mailbox>, ApiError> {
        validate_path_segment(domain, "domain")?;
        let mut all_mailboxes = Vec::new();
        let mut offset = 0;
        let limit = page_size.unwrap_or(50);

        loop {
            let params = PageParams {
                offset: Some(offset),
                limit: Some(limit),
            };
            let path = self.customer_path(&format!("/domains/{}/rs/mailboxes", domain))?;
            let resp: PagedResponse<MailboxList> = self
                .request::<PagedResponse<MailboxList>, (), PageParams>(
                    Method::GET,
                    &path,
                    None,
                    Some(&params),
                    false,
                )
                .await?;

            let batch_size = resp.items.mailboxes.len();
            all_mailboxes.extend(resp.items.mailboxes);

            if batch_size < limit || all_mailboxes.len() >= resp.total {
                break;
            }
            offset += batch_size;
        }
        Ok(all_mailboxes)
    }

    /// Retrieves details for a specific Rackspace Email mailbox.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn get_rackspace_mailbox(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<Mailbox, ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(name, "mailbox name")?;
        let path = self.customer_path(&format!("/domains/{}/rs/mailboxes/{}", domain, name))?;
        self.request::<Mailbox, (), ()>(Method::GET, &path, None, None, false)
            .await
    }

    /// Creates a new Rackspace Email mailbox.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn create_rackspace_mailbox(
        &self,
        domain: &str,
        mailbox: &Mailbox,
    ) -> Result<Mailbox, ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(&mailbox.name, "mailbox name")?;
        let path = self.customer_path(&format!("/domains/{}/rs/mailboxes", domain))?;
        self.request::<Mailbox, Mailbox, ()>(Method::POST, &path, Some(mailbox), None, false)
            .await
    }

    /// Updates an existing Rackspace Email mailbox.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn update_rackspace_mailbox(
        &self,
        domain: &str,
        mailbox: &Mailbox,
    ) -> Result<Mailbox, ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(&mailbox.name, "mailbox name")?;
        let path = self.customer_path(&format!(
            "/domains/{}/rs/mailboxes/{}",
            domain, mailbox.name
        ))?;
        self.request::<Mailbox, Mailbox, ()>(Method::PUT, &path, Some(mailbox), None, false)
            .await
    }

    /// Deletes a Rackspace Email mailbox.
    ///
    /// Note: This applies to Rackspace email accounts, distinct from Exchange email accounts.
    pub async fn delete_rackspace_mailbox(&self, domain: &str, name: &str) -> Result<(), ApiError> {
        validate_path_segment(domain, "domain")?;
        validate_path_segment(name, "mailbox name")?;
        let path = self.customer_path(&format!("/domains/{}/rs/mailboxes/{}", domain, name))?;
        self.request::<(), (), ()>(Method::DELETE, &path, None, None, false)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Debug)]
    struct MockClock;

    impl Clock for MockClock {
        fn timestamp(&self) -> String {
            "20230101120000".to_string()
        }
    }

    #[test]
    fn test_signature_generation_known_vector() {
        #[derive(Debug)]
        struct FixedClock;
        impl Clock for FixedClock {
            fn timestamp(&self) -> String {
                "20010308143725".to_string()
            }
        }

        let client = RackspaceClient::new(
            "eGbq9/2hcZsRlr1JV1Pi",
            "QHOvchm/40czXhJ1OxfxK7jDHr3t",
            None,
            Some("Rackspace Management Interface"),
        )
        .unwrap()
        .with_clock(Box::new(FixedClock));

        let signature = client.generate_signature();
        assert_eq!(
            signature,
            "eGbq9/2hcZsRlr1JV1Pi:20010308143725:46VIwd66mOFGG8IkbgnLlXnfnkU="
        );
    }

    /// Verifies that the client correctly generates and sends the X-Api-Signature header.
    ///
    /// This test ensures:
    /// 1. The signature is calculated using the correct formula: SHA1(key + ua + timestamp + secret).
    /// 2. The timestamp is retrieved from the injected Clock (MockClock).
    /// 3. The header is properly formatted and attached to the HTTP request.
    #[tokio::test]
    async fn test_list_domains_signature() {
        let mock_server = MockServer::start().await;

        let user_key = "test_key";
        let secret_key = "test_secret";
        let user_agent = "TestAgent";
        let timestamp = "20230101120000"; // Based on MockClock

        // Calculate expected signature manually
        let mut hasher = Sha1::new();
        hasher.update(user_key.as_bytes());
        hasher.update(user_agent.as_bytes());
        hasher.update(timestamp.as_bytes());
        hasher.update(secret_key.as_bytes());
        let hash = hasher.finalize();
        let sig_hash = general_purpose::STANDARD.encode(hash);
        let expected_header = format!("{}:{}:{}", user_key, timestamp, sig_hash);

        let client = RackspaceClient::new(
            user_key,
            secret_key,
            Some("123"),
            Some(user_agent),
        )
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_clock(Box::new(MockClock));

        Mock::given(method("GET"))
            .and(path("/customers/123/domains"))
            .and(header("X-Api-Signature", expected_header.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "domains": [],
                "total": 0,
                "offset": 0,
                "size": 50
            })))
            .mount(&mock_server)
            .await;

        let result = client.list_domains(None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_domains_parsing() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        let response_body = serde_json::json!({
            "domains": [
                {"accountNumber":"123456","exchangeMaxNumMailboxes":0,"exchangeUsedStorage":0,"name":"domain-1.com","rsEmailMaxNumberMailboxes":0,"rsEmailUsedStorage":1,"serviceType":"rsemail"},
                {"accountNumber":"123456","exchangeMaxNumMailboxes":0,"exchangeUsedStorage":0,"name":"domain-2.com","rsEmailMaxNumberMailboxes":0,"rsEmailUsedStorage":0,"serviceType":"rsemail"},
            ],
            "offset": 0,
            "size": 50,
            "total": 2
        });

        Mock::given(method("GET"))
            .and(path("/domains"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let domains = client
            .list_domains(None)
            .await
            .expect("Failed to list domains");

        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].name, "domain-1.com");
        assert_eq!(domains[0].service_type, Some("rsemail".to_string()));
    }

    #[tokio::test]
    async fn test_list_domains_pagination() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        // Page 1: 50 items (Full page, triggers next fetch)
        let mut domains_page1 = Vec::new();
        for i in 0..50 {
            domains_page1.push(serde_json::json!({
                "name": format!("p1-domain-{}.com", i),
                "serviceType": "rsemail"
            }));
        }
        let response_page1 = serde_json::json!({
            "domains": domains_page1,
            "offset": 0,
            "size": 50,
            "total": 60
        });

        // Page 2: 10 items (Partial page, stops fetch)
        let mut domains_page2 = Vec::new();
        for i in 0..10 {
            domains_page2.push(serde_json::json!({
                "name": format!("p2-domain-{}.com", i),
                "serviceType": "rsemail"
            }));
        }
        let response_page2 = serde_json::json!({
            "domains": domains_page2,
            "offset": 50,
            "size": 50,
            "total": 60
        });

        Mock::given(method("GET"))
            .and(path("/domains"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_page1))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/domains"))
            .and(query_param("offset", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_page2))
            .mount(&mock_server)
            .await;

        let domains = client
            .list_domains(None)
            .await
            .expect("Failed to list domains");

        assert_eq!(domains.len(), 60);
        assert_eq!(domains[0].name, "p1-domain-0.com");
        assert_eq!(domains[50].name, "p2-domain-0.com");
    }

    #[tokio::test]
    async fn test_list_mailboxes_parsing() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        let response_body = serde_json::json!({
            "offset": 0,
            "rsMailboxes": [
                {"name": "user1", "displayName": "User One"},
                {"name": "user2", "displayName": "User Two"}
            ],
            "size": 50,
            "total": 2
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/mailboxes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let mailboxes = client
            .list_rackspace_mailboxes("example.com", None)
            .await
            .expect("Failed to list mailboxes");

        assert_eq!(mailboxes.len(), 2);
        assert_eq!(mailboxes[0].name, "user1");
        assert_eq!(mailboxes[1].name, "user2");
    }

    #[tokio::test]
    async fn test_list_mailboxes_pagination() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        // Page 1: 50 items
        let mut mailboxes_page1 = Vec::new();
        for i in 0..50 {
            mailboxes_page1.push(serde_json::json!({
                "name": format!("user-p1-{}", i),
                "displayName": format!("User P1 {}", i)
            }));
        }
        let response_page1 = serde_json::json!({
            "rsMailboxes": mailboxes_page1,
            "offset": 0,
            "size": 50,
            "total": 60
        });

        // Page 2: 10 items
        let mut mailboxes_page2 = Vec::new();
        for i in 0..10 {
            mailboxes_page2.push(serde_json::json!({
                "name": format!("user-p2-{}", i),
                "displayName": format!("User P2 {}", i)
            }));
        }
        let response_page2 = serde_json::json!({
            "rsMailboxes": mailboxes_page2,
            "offset": 50,
            "size": 50,
            "total": 60
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/mailboxes"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_page1))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/mailboxes"))
            .and(query_param("offset", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_page2))
            .mount(&mock_server)
            .await;

        let mailboxes = client
            .list_rackspace_mailboxes("example.com", None)
            .await
            .expect("Failed to list mailboxes");

        assert_eq!(mailboxes.len(), 60);
        assert_eq!(mailboxes[0].name, "user-p1-0");
        assert_eq!(mailboxes[50].name, "user-p2-0");
    }

    #[tokio::test]
    async fn test_list_aliases_parsing() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        let response_body = serde_json::json!({
            "aliases": [
                {"name":"obfuscated_alias_1","numberOfMembers":1,"singleMemberName":"user1@example.com"},
                {"name":"obfuscated_alias_2","numberOfMembers":1,"singleMemberName":"user2@example.com"}
            ],
            "offset": 0,
            "size": 50,
            "total": 2
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/aliases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let aliases = client
            .list_rackspace_aliases("example.com", None)
            .await
            .expect("Failed to list aliases");

        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases[0].alias, "obfuscated_alias_1");
        assert_eq!(aliases[0].email_list, vec!["user1@example.com"]);
        assert_eq!(aliases[1].alias, "obfuscated_alias_2");
        assert_eq!(aliases[1].email_list, vec!["user2@example.com"]);
    }

    #[tokio::test]
    async fn test_get_alias_parsing_detailed() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        let response_body = serde_json::json!({
            "name": "testing",
            "emailAddressList": {
                "emailAddress": ["user1@example.com", "user2@example.com"]
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/aliases/testing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let alias = client
            .get_rackspace_alias("example.com", "testing")
            .await
            .expect("Failed to get alias");

        assert_eq!(alias.alias, "testing");
        assert_eq!(
            alias.email_list,
            vec!["user1@example.com", "user2@example.com"]
        );
    }

    #[tokio::test]
    async fn test_list_aliases_pagination() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        // Page 1: 50 items
        let mut aliases_page1 = Vec::new();
        for i in 0..50 {
            aliases_page1.push(serde_json::json!({
                "name": format!("alias-p1-{}", i),
                "numberOfMembers": 1,
                "singleMemberName": format!("user-p1-{}@example.com", i)
            }));
        }
        let response_page1 = serde_json::json!({
            "aliases": aliases_page1,
            "offset": 0,
            "size": 50,
            "total": 60
        });

        // Page 2: 10 items
        let mut aliases_page2 = Vec::new();
        for i in 0..10 {
            aliases_page2.push(serde_json::json!({
                "name": format!("alias-p2-{}", i),
                "numberOfMembers": 1,
                "singleMemberName": format!("user-p2-{}@example.com", i)
            }));
        }
        let response_page2 = serde_json::json!({
            "aliases": aliases_page2,
            "offset": 50,
            "size": 50,
            "total": 60
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/aliases"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_page1))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/aliases"))
            .and(query_param("offset", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_page2))
            .mount(&mock_server)
            .await;

        let aliases = client
            .list_rackspace_aliases("example.com", None)
            .await
            .expect("Failed to list aliases");

        assert_eq!(aliases.len(), 60);
        assert_eq!(aliases[0].alias, "alias-p1-0");
        assert_eq!(aliases[50].alias, "alias-p2-0");
    }

    #[tokio::test]
    async fn test_throttling_retry_success() {
        tokio::time::pause();

        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        // Mock 2: Success (Mounted first, checked last due to LIFO)
        let response_body = serde_json::json!({
            "domains": [],
            "offset": 0,
            "size": 50,
            "total": 0
        });

        Mock::given(method("GET"))
            .and(path("/domains"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        // Mock 1: Throttling error (happens once)
        Mock::given(method("GET"))
            .and(path("/domains"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Exceeded request limits"))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        let result = client.list_domains(None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_throttling_retry_exhaustion() {
        tokio::time::pause();

        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        // Always return throttling error
        Mock::given(method("GET"))
            .and(path("/domains"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Exceeded request limits"))
            .mount(&mock_server)
            .await;

        let result = client.list_domains(None).await;
        assert!(result.is_err());
        if let Err(ApiError::Http { status, body }) = result {
            assert_eq!(status, 403);
            assert!(body.contains("Exceeded request limits"));
        } else {
            panic!("Unexpected error type");
        }
    }

    #[tokio::test]
    async fn test_throttling_no_retries() {
        tokio::time::pause();

        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock))
            .with_max_retries(0);

        // Expect exactly 1 call because retries are disabled
        Mock::given(method("GET"))
            .and(path("/domains"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Exceeded request limits"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_domains(None).await;
        assert!(result.is_err());
        if let Err(ApiError::Http { status, body }) = result {
            assert_eq!(status, 403);
            assert!(body.contains("Exceeded request limits"));
        } else {
            panic!("Unexpected error type");
        }
    }

    #[tokio::test]
    async fn test_list_aliases_multi_member() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        let list_response = serde_json::json!({
            "aliases": [
                {"name": "simple", "numberOfMembers": 1, "singleMemberName": "simple@example.com"},
                {"name": "complex", "numberOfMembers": 2, "singleMemberName": null}
            ],
            "offset": 0,
            "size": 50,
            "total": 2
        });

        let detail_response = serde_json::json!({
            "name": "complex",
            "emailAddressList": {
                "emailAddress": ["a@example.com", "b@example.com"]
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/aliases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(list_response))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/domains/example.com/rs/aliases/complex"))
            .respond_with(ResponseTemplate::new(200).set_body_json(detail_response))
            .mount(&mock_server)
            .await;

        let aliases = client
            .list_rackspace_aliases("example.com", None)
            .await
            .expect("Failed to list aliases");

        assert_eq!(aliases.len(), 2);

        let simple = aliases.iter().find(|a| a.alias == "simple").unwrap();
        assert_eq!(simple.email_list, vec!["simple@example.com"]);

        let complex = aliases.iter().find(|a| a.alias == "complex").unwrap();
        assert_eq!(complex.email_list, vec!["a@example.com", "b@example.com"]);
    }

    #[tokio::test]
    async fn test_create_rackspace_alias() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        let alias = Alias {
            alias: "new_alias".to_string(),
            email_list: vec!["a@example.com".to_string(), "b@example.com".to_string()],
        };

        Mock::given(method("POST"))
            .and(path("/domains/example.com/rs/aliases/new_alias"))
            .and(header("Content-Type", "application/x-www-form-urlencoded"))
            // serde_urlencoded encodes space as + and comma as %2C
            .and(body_string(
                "aliasEmails=a%40example.com%2C+b%40example.com",
            ))
            .respond_with(ResponseTemplate::new(200)) // Empty body
            .mount(&mock_server)
            .await;

        let result = client.create_rackspace_alias("example.com", &alias).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_rackspace_alias() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        let alias = Alias {
            alias: "existing_alias".to_string(),
            email_list: vec!["updated@example.com".to_string()],
        };

        Mock::given(method("PUT"))
            .and(path("/domains/example.com/rs/aliases/existing_alias"))
            .and(header("Content-Type", "application/x-www-form-urlencoded"))
            .and(body_string("aliasEmails=updated%40example.com"))
            .respond_with(ResponseTemplate::new(200)) // Empty body
            .mount(&mock_server)
            .await;

        let result = client.update_rackspace_alias("example.com", &alias).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_rackspace_alias() {
        let mock_server = MockServer::start().await;
        let client = RackspaceClient::new("key", "secret", None, None)
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_clock(Box::new(MockClock));

        Mock::given(method("DELETE"))
            .and(path("/domains/example.com/rs/aliases/del_alias"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let result = client
            .delete_rackspace_alias("example.com", "del_alias")
            .await;
        assert!(result.is_ok());
    }
}
