use std::time::Duration;

use reqx::advanced::TimeoutPhase;
use reqx::prelude::{Client, Error, RetryPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://postman-echo.com")
        .client_name("reqx-example-overrides")
        .request_timeout(Duration::from_secs(2))
        .total_timeout(Some(Duration::from_secs(8)))
        .retry_policy(RetryPolicy::standard().max_attempts(3))
        .build()?;

    let fast = client
        .get("/delay/1")
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .send()
        .await;

    match fast {
        Ok(response) => {
            println!("unexpected success: status={}", response.status());
        }
        Err(Error::Timeout { phase, .. }) if phase == TimeoutPhase::Transport => {
            println!("request-level timeout works: phase={phase}");
        }
        Err(other) => {
            println!("request failed with: {other}");
        }
    }

    let stable = client
        .get("/get")
        .request_timeout(Duration::from_secs(2))
        // Disable the inherited overall deadline; the per-attempt timeout still applies.
        .total_timeout(None)
        .retry_policy(RetryPolicy::standard().max_attempts(2))
        .send()
        .await?;

    println!("GET /get => status={}", stable.status());
    Ok(())
}
