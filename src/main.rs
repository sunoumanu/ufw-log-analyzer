// main.rs
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use chrono::{NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::process;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time;
use moka::future::Cache;
use std::sync::Arc;

// First, modify the AppCache structure to explicitly use Vec<IpInfo>
struct AppCache {
    ip_info_cache: Cache<String, Vec<IpInfo>>,  // Changed to Vec<IpInfo>
}

impl AppCache {
    fn new() -> Self {
        Self {
            ip_info_cache: Cache::builder()
                .time_to_live(Duration::from_secs(300))
                .build(),
        }
    }
}

// Add cache to your application state
static APP_CACHE: Lazy<Arc<AppCache>> = Lazy::new(|| {
    Arc::new(AppCache::new())
});


// Global database connection pool using a wrapper that implements Send + Sync
struct DatabaseConnection {
    path: String,
}

impl DatabaseConnection {
    fn new(path: &str) -> Self {
        DatabaseConnection {
            path: path.to_string(),
        }
    }

    fn get_connection(&self) -> SqliteResult<Connection> {
        let conn = Connection::open(&self.path)?;
        Ok(conn)
    }
}

// Safety: We're ensuring thread-safe access through explicit connection management
static DB_POOL: Lazy<DatabaseConnection> = Lazy::new(|| {
    let db_conn = DatabaseConnection::new("ufw_logs.db");
    // Initialize the database
    let conn = db_conn.get_connection().expect("Failed to open database");
    setup_database(&conn).expect("Failed to setup database");
    db_conn
});

// IP Address with whois information
#[derive(Serialize, Deserialize, Clone)]
struct IpInfo {
    ip: String,
    dest_port: String,
    first_seen: String,
    last_seen: String,
    whois_info: Option<String>,
    whois_updated: Option<String>,
}

// Setup database tables
fn setup_database(conn: &Connection) -> SqliteResult<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_logs (
            ip TEXT PRIMARY KEY,
            dest_port TEXT,
            first_seen TIMESTAMP NOT NULL,
            last_seen TIMESTAMP NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS whois_data (
            ip TEXT PRIMARY KEY,
            whois_info TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            FOREIGN KEY (ip) REFERENCES ip_logs(ip)
        )",
        [],
    )?;

    Ok(())
}

// Extract IP addresses from UFW log entries
fn extract_ip_from_log(log_line: &str) -> Option<(String, String)> {
    static IP_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*DPT=(\d+)").unwrap()
    });

    IP_REGEX.captures(log_line).map(|cap| (cap[1].to_string(), cap[2].to_string()))
}

// Parse journalctl output and store IPs in the database
async fn process_ufw_logs() -> SqliteResult<()> {
    println!("Processing UFW logs...");

    let mut child = std::process::Command::new("journalctl")
        .args(&["--no-pager", "-n", "1000"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to execute journalctl command");

    let output = child.wait_with_output()
        .expect("Failed to wait for journalctl command");

    if !output.status.success() {
        eprintln!("journalctl command failed: {}",
                  String::from_utf8_lossy(&output.stderr));
    }

    let log_lines = String::from_utf8_lossy(&output.stdout);

    let now = Utc::now().naive_utc();

    let conn = DB_POOL.get_connection()?;

    println!("Total lines in ufw logs found: {}", log_lines.len());

    for line in log_lines.lines() {
        println!("Line for IP {}", line);
        if let Some((ip, port)) = extract_ip_from_log(line) {
            println!("Extracted IP {}", ip);
            // Try to update existing record first
            let updated = conn.execute(
                "UPDATE ip_logs SET last_seen = ?1, dest_port = ?2 WHERE ip = ?3",
                params![now, port, ip],
            )?;

            // If no records were updated, insert a new record
            if updated == 0 {
                conn.execute(
                    "INSERT INTO ip_logs (ip, dest_port, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4)",
                    params![ip, port, now, now],
                )?;
            }
        }
    }

    // Invalidate cache after processing new logs
    APP_CACHE.ip_info_cache.invalidate_all();

    Ok(())
}

// Perform whois lookup for an IP and store the result
async fn perform_whois_lookup(ip: &str) -> SqliteResult<()> {
    println!("Performing whois lookup for IP: {}", ip);

    let mut child = std::process::Command::new("whois")
        .arg(ip)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to execute whois command");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    // Wait for the child process to complete
    child.wait().expect("Failed to wait for child process");

    let mut found_marker = false;

    let mut whois_info = String::new();
    for line in reader.lines() {
        if let Ok(line) = line {
            if !found_marker {
                if line.contains("% Information related to") || line.contains("# start")
                    || line.contains("NetRange:") || line.contains("ENGLISH") {
                    found_marker = true;
                    whois_info.push_str(&line);
                    whois_info.push('\n');
                }
            } else {
                whois_info.push_str(&line);
                whois_info.push('\n');
            }
        }
    }

    // update only if whois not empty
    if !whois_info.is_empty() {
        // Try to update existing record first
        let now = Utc::now().naive_utc();
        // Get a fresh connection
        let conn = DB_POOL.get_connection()?;

        let updated = conn.execute(
            "UPDATE whois_data SET whois_info = ?1, updated_at = ?2 WHERE ip = ?3",
            params![whois_info, now, ip],
        )?;

        // If no records were updated, insert a new record
        if updated == 0 {
            conn.execute(
                "INSERT INTO whois_data (ip, whois_info, updated_at) VALUES (?1, ?2, ?3)",
                params![ip, whois_info, now],
            )?;
        }

        // Invalidate cache after updating whois data
        APP_CACHE.ip_info_cache.invalidate_all();
    }

    Ok(())
}

// Check for new IPs that need whois lookup
async fn process_whois_lookups() -> SqliteResult<()> {
    println!("Processing whois lookups...");

    // First collect all IPs that need updating - this approach avoids holding DB resources across await points
    let ips_to_update = {
        let conn = DB_POOL.get_connection()?;

        // Find IPs without whois data or with outdated whois data
        let mut stmt = conn.prepare(
            "SELECT ip_logs.ip FROM ip_logs
             LEFT JOIN whois_data ON ip_logs.ip = whois_data.ip
             WHERE whois_data.ip IS NULL
             OR whois_data.whois_info IS NULL
             OR whois_data.whois_info  = ''
             OR (julianday('now') - julianday(whois_data.updated_at)) > 1"
        )?;

        let ip_rows = stmt.query_map([], |row| {
            let ip: String = row.get(0)?;
            Ok(ip)
        })?;

        // Collect all IPs into a Vec to avoid holding the DB connection across await points
        let ips: Vec<String> = ip_rows.filter_map(Result::ok).collect();
        ips
    };

    // Process each IP - now we don't have any DB resources held across await points
    for ip in ips_to_update {
        perform_whois_lookup(&ip).await?;
        // Add a small delay to avoid overwhelming the whois server
        time::sleep(Duration::from_millis(5000)).await;
    }

    Ok(())
}

// Web handler for the main page
#[get("/")]
async fn index() -> impl Responder {
    // Try to get data from cache first
    if let Some(cached_data) = APP_CACHE.ip_info_cache.get("ip_list") {
        return generate_html_response(cached_data.as_slice());
    }

    let conn = DB_POOL.get_connection().expect("Failed to get DB connection");

    // Get all IPs with their whois information
    let mut stmt = conn.prepare(
        "SELECT
            ip_logs.ip,
            ip_logs.dest_port,
            strftime('%Y-%m-%d %H:%M:%S', ip_logs.first_seen),
            strftime('%Y-%m-%d %H:%M:%S', ip_logs.last_seen),
            whois_data.whois_info,
            strftime('%Y-%m-%d %H:%M:%S', whois_data.updated_at)
         FROM ip_logs
         LEFT JOIN whois_data ON ip_logs.ip = whois_data.ip
         ORDER BY ip_logs.last_seen DESC"
    ).expect("Failed to prepare statement");

    let ip_rows = stmt.query_map([], |row| {
        let ip: String = row.get(0)?;
        let dest_port: String = row.get(1)?;
        let first_seen: NaiveDateTime = row.get(2)?;
        let last_seen: NaiveDateTime = row.get(3)?;
        let whois_info: Option<String> = row.get(4).ok();
        let whois_updated: Option<NaiveDateTime> = row.get(5).ok();

        Ok(IpInfo {
            ip,
            dest_port,
            first_seen: first_seen.to_string(),
            last_seen: last_seen.to_string(),
            whois_info,
            whois_updated: whois_updated.map(|dt| dt.to_string()),
        })
    }).expect("Failed to execute query");


    let ip_list: Vec<IpInfo> = ip_rows.filter_map(Result::ok).collect();

    // Store in cache
    APP_CACHE.ip_info_cache.insert("ip_list".to_string(), ip_list.clone()).await;

    generate_html_response(&ip_list)
}


// Separate HTML generation function
fn generate_html_response(ip_list: &[IpInfo]) -> HttpResponse {
    // Generate HTML
    let mut html = String::from(
        "<!DOCTYPE html>
        <html>
        <head>
            <title>UFW Log Analyzer</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                h1 { color: #333; }
                table { border-collapse: collapse; width: 100%; }
                th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
                tr:hover { background-color: #f5f5f5; }
                th { background-color: #4CAF50; color: white; }
                .whois { max-height: 150px; overflow-y: auto; white-space: pre-wrap; }
                .container { max-width: 1200px; margin: 0 auto; }
            </style>
        </head>
        <body>
            <div class='container'>
                <h1>UFW Log IP Addresses who tried get into this machine</h1>
                <p>Total unique IPs found: ".to_string() + &ip_list.len().to_string() + "</p>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Last probed port</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>Whois Updated</th>
                        <th>Whois Information</th>
                    </tr>"
    );

    for ip_info in ip_list {
        html += &format!(
            "<tr>
                <td>{}</td>
                <td><a href=https://www.speedguide.net/port.php?port={}>{}</a></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td><div class='whois'>{}</div></td>
            </tr>",
            ip_info.ip,
            ip_info.dest_port, ip_info.dest_port,
            ip_info.first_seen,
            ip_info.last_seen,
            ip_info.whois_updated.as_deref().unwrap_or("Not updated"),
            ip_info.whois_info.as_deref().unwrap_or("No data")
        );
    }

    html += "</table></div></body></html>";

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// Schedule periodic tasks (log processing and whois lookups)
async fn start_schedulers() {
    // Process logs every 5 minutes
    let log_interval = Duration::from_secs(300);
    tokio::spawn(async move {
        loop {
            // Each execution is isolated and doesn't hold resources across await points
            if let Err(e) = process_ufw_logs().await {
                eprintln!("Error processing UFW logs: {}", e);
            }
            time::sleep(log_interval).await;
        }
    });

    // Process whois lookups once per hour
    let whois_interval = Duration::from_secs(3600);
    tokio::spawn(async move {
        loop {
            // Each execution is isolated and doesn't hold resources across await points
            if let Err(e) = process_whois_lookups().await {
                eprintln!("Error processing whois lookups: {}", e);
            }
            time::sleep(whois_interval).await;
        }
    });
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting UFW Log Analyzer...");

    // Initial processing
    if let Err(e) = process_ufw_logs().await {
        eprintln!("Error during initial UFW log processing: {}", e);
    }

    // Start schedulers
    start_schedulers().await;

    // Start HTTP server
    println!("Starting HTTP server on http://0.0.0.0:8080");
    HttpServer::new(|| {
        App::new()
            .service(index)
    })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}