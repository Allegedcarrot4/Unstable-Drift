use drift::WispClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WispClient::builder().build()?;
    let resp = client.get("https://httpbin.org/get").send().await?;
    println!("status: {}", resp.status());
    for h in resp.headers() {
        println!("{}: {}", h.name, h.value);
    }
    println!("body: {}", resp.text()?);
    Ok(())
}
