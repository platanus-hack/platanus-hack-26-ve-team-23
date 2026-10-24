//! Stress and abuse run against a live Core (ADR-0028, ADR-0029).
//!
//! ```text
//! stress [ADDR] [--hosts N] [--calls M] [--concurrency C] [--churn K] [--report FILE]
//! ```
//!
//! Pairs a fresh, unpaired Core as a throwaway owner and app, enrols `N`
//! hosts, drives `M` decisions per host with `C` in flight, then runs the
//! identity and abuse cases and checks the Core's answer to each. Prints a
//! Markdown report (and writes it to `--report`). Exits non-zero if any
//! check fails.
//!
//! It pairs the Core it is pointed at: run it only against a Core started
//! for the purpose, with an empty `GUARDIAN_DATA_DIR`.

#![forbid(unsafe_code)]

use std::{
    fmt::Write as _,
    net::SocketAddr,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use edge_net::quic::{self, PeerId};
use guardian_core::{
    keys::CorePublic,
    machine::{Mac, Nic},
    pairing::{confirmation_code, pair_message},
    seal,
    wire::{approve_message, HostApproval, HostInfo, Request, Response},
    Decision, SignedHead, ToolCall,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use quinn::Connection;
use rand::{rngs::OsRng, RngCore};
use tokio::sync::Semaphore;

const CALL_TIMEOUT: Duration = Duration::from_secs(30);

struct Args {
    addr: SocketAddr,
    hosts: usize,
    calls: usize,
    concurrency: usize,
    churn: usize,
    report: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        addr: "127.0.0.1:7443".parse().map_err(|_| "bad default")?,
        hosts: 16,
        calls: 250,
        concurrency: 64,
        churn: 1100,
        report: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--hosts" => args.hosts = value("--hosts")?.parse().map_err(|_| "bad --hosts")?,
            "--calls" => args.calls = value("--calls")?.parse().map_err(|_| "bad --calls")?,
            "--concurrency" => {
                args.concurrency = value("--concurrency")?
                    .parse()
                    .map_err(|_| "bad --concurrency")?;
            }
            "--churn" => args.churn = value("--churn")?.parse().map_err(|_| "bad --churn")?,
            "--report" => args.report = Some(value("--report")?),
            other => args.addr = other.parse().map_err(|_| format!("bad address {other}"))?,
        }
    }
    Ok(args)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn random_hwid() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

async fn call(conn: &Connection, req: &Request) -> Result<Response, String> {
    quic::request(conn, req, CALL_TIMEOUT).await
}

/// The throwaway owner and app that pair the Core.
struct Owner {
    _client: quic::Client,
    conn: Connection,
    core: [u8; 32],
    core_public: CorePublic,
    key: SigningKey,
}

async fn pair(addr: SocketAddr) -> Result<Owner, String> {
    let device = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let client = quic::Client::new(quic::TlsIdentity::from_signing_key(
        &device,
        "hawk-witness",
    )?)?;
    let (conn, core) = client.connect(addr, None).await?;
    let (core_public, nonce) = match call(&conn, &Request::PairOffer).await? {
        Response::Offer { core_public, nonce } => (core_public, nonce),
        other => return Err(format!("the Core is not unpaired: {other:?}")),
    };
    let key = SigningKey::random(&mut OsRng);
    let mut epoch = [0u8; 32];
    OsRng.fill_bytes(&mut epoch);
    let nonce = hex::decode(nonce).map_err(|_| "bad nonce")?;
    let owner_public = key.verifying_key().to_encoded_point(true);
    let signature: Signature = key.sign(&pair_message(
        &nonce,
        &core,
        &core_public,
        &device.verifying_key().to_bytes(),
    ));
    let request = Request::Pair {
        owner_public: hex::encode(owner_public.as_bytes()),
        epoch_public: hex::encode(seal::epoch_public(&epoch)),
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    match call(&conn, &request).await? {
        Response::Paired {
            confirmation_code: code,
        } if code == confirmation_code(&core, &core_public, owner_public.as_bytes()) => {}
        other => return Err(format!("pairing failed: {other:?}")),
    }
    Ok(Owner {
        _client: client,
        conn,
        core,
        core_public,
        key,
    })
}

impl Owner {
    fn approval(&self, host: &PeerId, hwid: &str, at: u64, key: &SigningKey) -> HostApproval {
        let signature: Signature = key.sign(&approve_message(&self.core, host, hwid, at));
        HostApproval {
            core: hex::encode(self.core),
            host: hex::encode(host),
            hwid: hwid.into(),
            timestamp_ms: at,
            signature: hex::encode(signature.to_der().as_bytes()),
        }
    }

    async fn approve(&self, host: &PeerId, hwid: &str) -> Result<Response, String> {
        let approval = self.approval(host, hwid, now_ms(), &self.key);
        call(&self.conn, &Request::ApproveHost { approval }).await
    }

    async fn hosts(&self) -> Result<Vec<HostInfo>, String> {
        match call(&self.conn, &Request::Hosts).await? {
            Response::Hosts { hosts } => Ok(hosts),
            other => Err(format!("unexpected {other:?}")),
        }
    }
}

/// A simulated host daemon: its own key and QUIC endpoint.
struct Host {
    _client: quic::Client,
    key: ed25519_dalek::SigningKey,
    id: PeerId,
    hwid: String,
    conn: Connection,
}

async fn connect_as(
    addr: SocketAddr,
    core: PeerId,
    key: ed25519_dalek::SigningKey,
) -> Result<(quic::Client, Connection), String> {
    let client = quic::Client::new(quic::TlsIdentity::from_signing_key(&key, "hawk-host")?)?;
    let (conn, _) = client.connect(addr, Some(core)).await?;
    Ok((client, conn))
}

async fn hello(
    conn: &Connection,
    hostname: &str,
    hwid: &str,
    nics: Vec<Nic>,
) -> Result<(), String> {
    let req = Request::HostHello {
        hostname: hostname.into(),
        os: "stress".into(),
        hwid: hwid.into(),
        nics,
    };
    match call(conn, &req).await? {
        Response::Ack => Ok(()),
        other => Err(format!("hello refused: {other:?}")),
    }
}

async fn host(addr: SocketAddr, core: PeerId, name: &str, hwid: String) -> Result<Host, String> {
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let id = key.verifying_key().to_bytes();
    let (client, conn) = connect_as(addr, core, key.clone()).await?;
    hello(&conn, name, &hwid, Vec::new()).await?;
    Ok(Host {
        _client: client,
        key,
        id,
        hwid,
        conn,
    })
}

fn call_ls(n: usize) -> ToolCall {
    ToolCall {
        session: format!("stress-{n}"),
        tool: "bash".into(),
        args: serde_json::json!({ "command": "ls -la" }),
        cwd: "/work".into(),
        host: None,
        call_id: None,
    }
}

async fn decide(conn: &Connection, n: usize) -> Result<Decision, String> {
    match call(conn, &Request::Decide { call: call_ls(n) }).await? {
        Response::Decision { decision } => Ok(decision),
        other => Err(format!("unexpected {other:?}")),
    }
}

fn denied_because(decision: &Result<Decision, String>, why: &str) -> bool {
    matches!(decision, Ok(Decision::Deny { reason }) if reason.contains(why))
}

/// Latency percentiles of a sorted sample.
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}

#[derive(Default)]
struct Report {
    lines: String,
    checks: Vec<(String, bool, String)>,
}

impl Report {
    fn check(&mut self, name: &str, pass: bool, detail: impl Into<String>) {
        self.checks.push((name.into(), pass, detail.into()));
    }

    fn failed(&self) -> usize {
        self.checks.iter().filter(|c| !c.1).count()
    }

    fn render(&self) -> String {
        let mut out = self.lines.clone();
        let _ = writeln!(
            out,
            "\n## Checks\n\n| Result | Check | Detail |\n|---|---|---|"
        );
        for (name, pass, detail) in &self.checks {
            let mark = if *pass { "PASS" } else { "FAIL" };
            let _ = writeln!(out, "| {mark} | {name} | {} |", detail.replace('|', "/"));
        }
        let _ = writeln!(
            out,
            "\n{} of {} checks passed.",
            self.checks.len() - self.failed(),
            self.checks.len()
        );
        out
    }
}

async fn load(args: &Args, hosts: &[Host], report: &mut Report) {
    let latencies: Arc<Mutex<Vec<Duration>>> = Arc::default();
    let outcomes: Arc<Mutex<(usize, usize, usize)>> = Arc::default();
    let permits = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (h, host) in hosts.iter().enumerate() {
        for c in 0..args.calls {
            let conn = host.conn.clone();
            let permits = Arc::clone(&permits);
            let latencies = Arc::clone(&latencies);
            let outcomes = Arc::clone(&outcomes);
            tasks.push(tokio::spawn(async move {
                let Ok(_permit) = permits.acquire_owned().await else {
                    return;
                };
                let t = Instant::now();
                let result = decide(&conn, h * 100_000 + c).await;
                let took = t.elapsed();
                if let Ok(mut l) = latencies.lock() {
                    l.push(took);
                }
                if let Ok(mut o) = outcomes.lock() {
                    match result {
                        Ok(Decision::Allow) => o.0 += 1,
                        Ok(_) => o.1 += 1,
                        Err(_) => o.2 += 1,
                    }
                }
            }));
        }
    }
    for task in tasks {
        let _ = task.await;
    }
    let elapsed = started.elapsed();
    let mut sorted = latencies.lock().map(|l| l.clone()).unwrap_or_default();
    sorted.sort();
    let (allowed, denied, errors) = outcomes.lock().map(|o| *o).unwrap_or_default();
    let total = sorted.len();
    let rate = total as f64 / elapsed.as_secs_f64().max(0.001);
    let _ = writeln!(
        report.lines,
        "## Load\n\n{} approved hosts x {} calls, {} in flight: {total} decisions in {:.2} s, **{rate:.0} decisions/s**.\n\n\
         | p50 | p95 | p99 | max |\n|---|---|---|---|\n| {} | {} | {} | {} |\n\n\
         Allowed {allowed}, denied {denied}, errors {errors}.",
        hosts.len(),
        args.calls,
        args.concurrency,
        elapsed.as_secs_f64(),
        ms(percentile(&sorted, 0.50)),
        ms(percentile(&sorted, 0.95)),
        ms(percentile(&sorted, 0.99)),
        ms(sorted.last().copied().unwrap_or_default()),
    );
    report.check(
        "every approved call answered",
        errors == 0 && allowed == total,
        format!("{allowed} allowed of {total}, {errors} errors"),
    );
}

async fn abuse(
    args: &Args,
    owner: &Owner,
    hosts: &[Host],
    report: &mut Report,
) -> Result<(), String> {
    let addr = args.addr;
    let core = owner.core;

    // 1. A host the owner never approved, flooding.
    let stranger = host(addr, core, "stranger", random_hwid()).await?;
    let mut all_denied = true;
    let flood: Vec<_> = (0..200)
        .map(|n| {
            let conn = stranger.conn.clone();
            tokio::spawn(async move { decide(&conn, n).await })
        })
        .collect();
    for task in flood {
        let result = task.await.map_err(|e| e.to_string())?;
        all_denied &= denied_because(&result, "not approved");
    }
    report.check(
        "unapproved host is denied (200 calls)",
        all_denied,
        "fail closed: host not approved by the owner",
    );

    // 2. The approved key of host 0 copied to another machine.
    let victim = &hosts[0];
    let (_copy_client, copy) = connect_as(addr, core, victim.key.clone()).await?;
    hello(&copy, "copy", &random_hwid(), Vec::new()).await?;
    let copied = decide(&copy, 1).await;
    report.check(
        "approved key on another machine is denied",
        denied_because(&copied, "not approved"),
        format!("{copied:?}"),
    );
    let flagged = owner.hosts().await?.iter().any(|h| {
        h.id == hex::encode(victim.id)
            && h.conflict.as_deref().is_some_and(|c| c.contains("copied"))
    });
    report.check(
        "the copy is flagged to the owner",
        flagged,
        "conflict on the approved identity",
    );
    // The real machine says hello again and gets its decisions back.
    hello(&victim.conn, "host-0", &victim.hwid, Vec::new()).await?;
    let back = decide(&victim.conn, 2).await;
    report.check(
        "the real machine recovers on its next hello",
        matches!(back, Ok(Decision::Allow)),
        format!("{back:?}"),
    );
    copy.close(0u32.into(), b"done");

    // 3. A new daemon key on an approved machine (re-keying).
    let rekeyed = host(addr, core, "rekeyed", hosts[1].hwid.clone()).await?;
    let rk = decide(&rekeyed.conn, 3).await;
    let conflict = owner.hosts().await?.iter().any(|h| {
        h.id == hex::encode(rekeyed.id)
            && h.conflict
                .as_deref()
                .is_some_and(|c| c.contains("new daemon key"))
    });
    report.check(
        "re-keyed daemon on an approved machine is denied and flagged",
        denied_because(&rk, "not approved") && conflict,
        format!("{rk:?}, conflict shown: {conflict}"),
    );

    // 4-7. Approvals that must not work.
    let forger = SigningKey::random(&mut OsRng);
    let forged = owner.approval(&stranger.id, &stranger.hwid, now_ms(), &forger);
    let r = call(&owner.conn, &Request::ApproveHost { approval: forged }).await?;
    report.check(
        "forged approval (another owner key) refused",
        matches!(r, Response::Error { .. }),
        format!("{r:?}"),
    );

    let stale = owner.approval(&stranger.id, &stranger.hwid, now_ms() - 120_000, &owner.key);
    let r = call(&owner.conn, &Request::ApproveHost { approval: stale }).await?;
    report.check(
        "stale approval (2 min old) refused",
        matches!(r, Response::Error { .. }),
        format!("{r:?}"),
    );

    let r = owner.approve(&stranger.id, &random_hwid()).await?;
    report.check(
        "approval naming another HWID refused",
        matches!(r, Response::Error { .. }),
        format!("{r:?}"),
    );

    let own = owner.approval(&stranger.id, &stranger.hwid, now_ms(), &owner.key);
    let r = call(&stranger.conn, &Request::ApproveHost { approval: own }).await?;
    report.check(
        "a host cannot submit an approval (even a valid one)",
        matches!(r, Response::Error { .. }),
        format!("{r:?}"),
    );
    let still = decide(&stranger.conn, 4).await;
    report.check(
        "the stranger is still denied",
        denied_because(&still, "not approved"),
        format!("{still:?}"),
    );

    // 8. A host reading the record.
    let r = call(&stranger.conn, &Request::Events { since: None }).await?;
    report.check(
        "a host cannot read the record",
        matches!(r, Response::Error { .. }),
        format!("{r:?}"),
    );

    // 9-10. Oversized and malformed identifiers.
    let nics: Vec<Nic> = (0..5000u32)
        .map(|i| {
            let b = i.to_be_bytes();
            Nic::new(&format!("eth{i}"), Mac([2, 0, b[0], b[1], b[2], b[3]]))
        })
        .collect();
    let big = host(addr, core, "big", random_hwid()).await?;
    hello(
        &big.conn,
        &"x".repeat(10_000),
        "<img src=x onerror=alert(1)>",
        nics,
    )
    .await?;
    let listed = owner.hosts().await?;
    let entry = listed.iter().find(|h| h.id == hex::encode(big.id));
    report.check(
        "oversized hello is bounded (10 KB name, 5000 NICs)",
        entry.is_some_and(|h| h.hostname.chars().count() <= 64 && h.nics.len() <= 32),
        entry.map_or("host missing".into(), |h| {
            format!(
                "name {} chars, {} NICs kept",
                h.hostname.chars().count(),
                h.nics.len()
            )
        }),
    );
    report.check(
        "malformed HWID is dropped",
        entry.is_some_and(|h| h.hwid.is_empty()),
        entry.map_or("host missing".into(), |h| format!("hwid {:?}", h.hwid)),
    );

    // 11. Garbage on streams.
    let (mut send, _recv) = stranger.conn.open_bi().await.map_err(|e| e.to_string())?;
    let _ = send.write_all(&u32::MAX.to_be_bytes()).await;
    let _ = send.write_all(b"not json at all").await;
    let _ = send.finish();
    let (mut send, mut recv) = stranger.conn.open_bi().await.map_err(|e| e.to_string())?;
    let _ = send.write_all(&5u32.to_be_bytes()).await;
    let _ = send.write_all(b"{nope").await;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(1024)).await;
    let t = Instant::now();
    let alive = matches!(
        call(&owner.conn, &Request::Hello).await,
        Ok(Response::Hello { .. })
    );
    report.check(
        "garbage frames do not stop the Core",
        alive,
        format!("hello after garbage in {}", ms(t.elapsed())),
    );

    // 12. Key churn: an agent minting daemon keys in a loop.
    let started = Instant::now();
    let mut failures = 0usize;
    for chunk in (0..args.churn).collect::<Vec<_>>().chunks(50) {
        let batch: Vec<_> = chunk
            .iter()
            .map(|n| {
                let name = format!("churn-{n}");
                tokio::spawn(async move {
                    match host(addr, core, &name, random_hwid()).await {
                        Ok(h) => {
                            h.conn.close(0u32.into(), b"churn");
                            true
                        }
                        Err(_) => false,
                    }
                })
            })
            .collect();
        for task in batch {
            if !task.await.unwrap_or(false) {
                failures += 1;
            }
        }
    }
    let churn_time = started.elapsed();
    let listed = owner.hosts().await?.len();
    report.check(
        &format!(
            "{} minted daemon keys cannot grow the registry without bound",
            args.churn
        ),
        listed <= 1024,
        format!(
            "{listed} hosts listed after churn ({failures} connects failed, {:.1} s)",
            churn_time.as_secs_f64()
        ),
    );

    // 13. Still serving approved hosts, and the record still verifies.
    let t = Instant::now();
    let after = decide(&hosts[2 % hosts.len()].conn, 5).await;
    report.check(
        "approved host still served after the abuse",
        matches!(after, Ok(Decision::Allow)),
        format!("{after:?} in {}", ms(t.elapsed())),
    );
    let heads: Vec<SignedHead> = match call(&owner.conn, &Request::Heads { since: None }).await? {
        Response::Heads { heads } => heads,
        other => return Err(format!("unexpected {other:?}")),
    };
    let invalid = heads
        .iter()
        .filter(|h| h.verify(&owner.core_public).is_err())
        .count();
    report.check(
        "every signed head verifies (Ed25519 + ML-DSA-65)",
        !heads.is_empty() && invalid == 0,
        format!("{} heads, {invalid} invalid", heads.len()),
    );
    Ok(())
}

async fn run(args: Args) -> Result<Report, String> {
    let mut report = Report::default();
    let _ = writeln!(
        report.lines,
        "# HAWK stress run\n\nCore at `{}`, {} hosts x {} calls, {} in flight, {} churned keys.\n",
        args.addr, args.hosts, args.calls, args.concurrency, args.churn
    );
    let t = Instant::now();
    let owner = pair(args.addr).await?;
    let _ = writeln!(
        report.lines,
        "Paired as a throwaway owner in {}.",
        ms(t.elapsed())
    );

    let t = Instant::now();
    let mut hosts = Vec::new();
    for i in 0..args.hosts.max(3) {
        let h = host(args.addr, owner.core, &format!("host-{i}"), random_hwid()).await?;
        match owner.approve(&h.id, &h.hwid).await? {
            Response::Ack => {}
            other => return Err(format!("approval of host-{i} failed: {other:?}")),
        }
        hosts.push(h);
    }
    let _ = writeln!(
        report.lines,
        "Enrolled {} hosts (hello + owner approval) in {}.\n",
        hosts.len(),
        ms(t.elapsed())
    );
    let listed = owner.hosts().await?;
    report.check(
        "every enrolled host is listed as approved",
        hosts.iter().all(|h| {
            listed
                .iter()
                .any(|l| l.id == hex::encode(h.id) && l.approved && l.hwid == h.hwid)
        }),
        format!("{} listed", listed.len()),
    );

    load(&args, &hosts, &mut report).await;
    abuse(&args, &owner, &hosts, &mut report).await?;
    Ok(report)
}

// The report is the tool's output.
#[allow(clippy::print_stdout, clippy::print_stderr)]
#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("stress: {err}");
            return ExitCode::from(2);
        }
    };
    let path = args.report.clone();
    match run(args).await {
        Ok(report) => {
            let text = report.render();
            println!("{text}");
            if let Some(path) = path {
                if let Err(err) = std::fs::write(&path, &text) {
                    eprintln!("stress: could not write {path}: {err}");
                }
            }
            if report.failed() == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("stress: {err}");
            ExitCode::from(2)
        }
    }
}
