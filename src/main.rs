use std::{
    collections::HashMap,
    env,
    path::PathBuf,
    process::{self, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result};
use clap::Parser;
use dbus::{FdoLoginServiceProxy, FdoScreenSaverServiceProxy};
use futures_util::StreamExt as _;
use secret_service::{EncryptionType, SecretService};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf},
    process::{Child, Command},
    sync::{
        Mutex,
        mpsc::{self, UnboundedSender},
    },
    time,
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};
use zbus::Connection;

mod dbus;

/// A tool  to improve `rclone mount`
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_missing_value = "true")]
    log_timestamp: bool,

    /// The rclone config entry to be mounted
    #[arg(short, long)]
    rclone_entry: String,

    #[arg(long)]
    secret_target: Option<String>,

    /// Don't input password through stdin
    #[arg(short, long, default_missing_value = "true")]
    no_stdin_password: bool,

    /// Arguments passed to `rclone`
    #[arg(trailing_var_arg = true)]
    rclone_args: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum Event {
    StartSleepListener,
    StartUnlockListener,
    Mount,
    Unmount,
    Error,
}

struct RcloneProcessState {
    pid: Option<u32>,
    child: Mutex<Child>,
    alive: AtomicBool,
    closing: AtomicBool,
}

#[derive(Clone)]
struct RcloneProcess {
    state: Arc<RcloneProcessState>,
}

impl RcloneProcess {
    fn new(child: Child) -> Self {
        Self {
            state: Arc::new(RcloneProcessState {
                pid: child.id(),
                child: Mutex::new(child),
                alive: AtomicBool::new(true),
                closing: AtomicBool::new(false),
            }),
        }
    }

    fn is_alive(&self) -> bool {
        self.state.alive.load(Ordering::SeqCst)
    }

    fn is_closing(&self) -> bool {
        self.state.closing.load(Ordering::SeqCst)
    }

    async fn close(&mut self) {
        self.state.closing.store(true, Ordering::SeqCst);

        if !self.is_alive() {
            return;
        }

        if let Some(pid) = self.state.pid {
            if let Err(e) = cvt::cvt(unsafe { libc::kill(pid as i32, libc::SIGTERM) }).map(drop) {
                tracing::error!("Sending SIGTERM to {pid} failed: {e:#?}");
            }
        }

        if !self.is_alive() {
            return;
        }

        let sec = 5;
        tracing::warn!("Wait {sec} seconds for rclone to exit");
        let _ = time::sleep(Duration::from_secs(sec)).await;

        if !self.is_alive() {
            return;
        }

        if let Err(e) = self.state.child.lock().await.kill().await {
            tracing::warn!("Send SIGKILL error: {e:#?}");
        }
    }

    fn spawn_wait_then<F>(&self, f: F)
    where
        F: Fn() + Send + 'static,
    {
        tokio::spawn({
            let this = self.clone();
            async move {
                let mut child = this.state.child.lock().await;
                match child.wait().await {
                    Ok(status) => {
                        this.state.alive.store(false, Ordering::SeqCst);
                        if status.success() {
                            tracing::info!("Process[{:?}] exits", this.state.pid);
                            return;
                        } else {
                            tracing::error!(
                                "Process[{:?}] exits with status: {:?}",
                                this.state.pid,
                                status.code()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error waiting process[{:?}]: {e:#?}", this.state.pid);
                    }
                }
                if !this.is_closing() {
                    f()
                }
            }
        });
    }
}

struct AutoReset(Vec<u8>);

impl Drop for AutoReset {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// TODO hold item
///    // initialize secret service (dbus connection and encryption session)
///    let ss = SecretService::connect(EncryptionType::Dh).await.unwrap();
///
///    // get default collection
///    let collection = ss.get_default_collection().await.unwrap();
///
///    let mut properties = HashMap::new();
///    properties.insert("test", "test_value");
///
///    //create new item
///    collection.create_item(
///        "test_label", // label
///        properties,
///        b"test_secret", //secret
///        false, // replace item with same attributes
///        "text/plain" // secret content type
///    ).await.unwrap();
///
///    // search items by properties
///    let search_items = ss.search_items(
///        HashMap::from([("test", "test_value")])
///    ).await.unwrap();
///
///    // retrieve one item, first by checking the unlocked items
///    let item = match search_items.unlocked.first() {
///        Some(item) => item,
///        None => {
///            // if there aren't any, check the locked items and unlock the first one
///            let locked_item = search_items
///                .locked
///                .first()
///                .expect("Search didn't return any items!");
///            locked_item.unlock().await.unwrap();
///            locked_item
///        }
///    };
///
///    // retrieve secret from item
///    let secret = item.get_secret().await.unwrap();
struct PasswordEntry<'a> {
    // SecretService should be held, otherwise, keepassxc will prompt for authorization even in the same
    // process. It takes dbus address into consider.
    secret_service: Option<SecretService<'a>>,
    attributes: HashMap<String, String>,
}

impl<'a> PasswordEntry<'a> {
    fn new(target: Option<String>) -> Self {
        let mut attributes =
            HashMap::from([("service".to_string(), "rclone-mount-ext".to_string())]);
        if let Some(target) = target {
            attributes.insert("target".to_string(), target);
        }
        Self {
            secret_service: None,
            attributes,
        }
    }

    async fn get_password(&mut self) -> Result<AutoReset> {
        let secret_service = match self.secret_service.take() {
            Some(ss) => ss,
            None => SecretService::connect(EncryptionType::Dh).await?,
        };
        let attributes = self
            .attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let items = secret_service.search_items(attributes).await?;
        let total = items.locked.len() + items.unlocked.len();
        if total == 0 {
            anyhow::bail!("The password of `rclone` isn't found");
        } else if total != 1 {
            anyhow::bail!(
                "There are more than one item matchcing those attributes of the password of `rclone`"
            );
        }
        let password = if items.unlocked.len() == 1 {
            items.unlocked[0].get_secret().await?
        } else {
            items.locked[0].unlock().await?;
            items.locked[0].get_secret().await?
        };
        self.secret_service = Some(secret_service);
        Ok(AutoReset(password))
    }
}

fn init_log(log_timestamp: bool) -> Result<()> {
    let subscriber = tracing_subscriber::registry().with(EnvFilter::from_default_env());
    if log_timestamp {
        subscriber.with(fmt::layer()).try_init()?;
    } else {
        subscriber.with(fmt::layer().without_time()).try_init()?;
    }

    Ok(())
}

fn mount_point(rclone_entry: &str) -> Result<String> {
    let Ok(xdg_runtime_dir) = env::var("XDG_RUNTIME_DIR") else {
        anyhow::bail!("XDG_RUNTIME_DIR isn't set");
    };
    let mut buf = PathBuf::from(xdg_runtime_dir);
    buf.push("app");
    buf.push("rclone");
    buf.push(rclone_entry);
    buf.to_str()
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("Invalid mount_point"))
}

async fn force_umount(mount_point: &str) {
    let mut command = Command::new("fusermount3");
    command.args(&["-uq", mount_point]);
    match command.output().await {
        Ok(o) => {
            tracing::info!("Result of `fusermount3`: {o:?}");
        }
        Err(e) => {
            tracing::error!("Error of running `fusermount3`: {e:#?}");
        }
    };
}

async fn read_and_log<R>(stream: R, pid: Option<u32>, is_err: bool)
where
    R: AsyncRead + Unpin,
{
    let mut line_buf = vec![];
    let mut reader = BufReader::new(stream);
    let mut buf = [0; 1024];
    loop {
        let mut buf = ReadBuf::new(&mut buf);
        match reader.read_buf(&mut buf).await {
            Ok(len) => {
                if len == 0 {
                    break;
                }
                for &b in buf.filled() {
                    if b == b'\n' {
                        if is_err {
                            tracing::error!(
                                "Process[{pid:?}], stderr: {}",
                                String::from_utf8_lossy(&line_buf)
                            );
                        } else {
                            tracing::info!(
                                "Process[{pid:?}], stdout: {}",
                                String::from_utf8_lossy(&line_buf)
                            );
                        }
                        line_buf.clear();
                    } else {
                        line_buf.push(b);
                    }
                }
            }
            Err(e) => {
                if is_err {
                    tracing::error!("Process[{pid:?}], Error to read from err stream: {e:#?}");
                } else {
                    tracing::error!("Process[{pid:?}], Error to read from out stream: {e:#?}");
                }
                break;
            }
        }
    }
}

async fn expect<R>(mut stream: R, pid: Option<u32>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    const EXPECTED: &[u8] = b"password:";
    let mut buf = vec![];
    let mut error = None;
    let mut count = 0;
    loop {
        let b = match stream.read_u8().await {
            Ok(b) => b,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        if b == b'\n' {
            // Don't think it is error during `expect`
            tracing::info!(
                "Process[{pid:?}], stderr: {}",
                String::from_utf8_lossy(&buf)
            );
            buf.clear();
        } else {
            buf.push(b);
            if buf.ends_with(EXPECTED) {
                count += 1;
                if count > 1 {
                    break;
                }
            }
        }
    }

    // Don't think it is error during `expect`
    tracing::info!(
        "Process[{pid:?}], stderr: {}",
        String::from_utf8_lossy(&buf)
    );

    match error {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

async fn mount(
    args: &Args,
    mount_point: &str,
    password_entry: &mut PasswordEntry<'_>,
) -> Result<RcloneProcess> {
    // `force_umount` should be run before accessing the folder, otherwise, a error might be
    // raised.
    force_umount(mount_point).await;

    // create mount_point if not exist
    if !fs::try_exists(mount_point).await? {
        fs::create_dir_all(mount_point).await?;
    }

    let mut command = Command::new("rclone");
    command
        .args(&[
            "mount",
            "--vfs-cache-mode",
            "full",
            &format!("{}:", args.rclone_entry),
            mount_point,
        ])
        .args(&args.rclone_args);

    command.stderr(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stdin(Stdio::piped());
    tracing::debug!("command to be run: {command:?}");

    let mut child = command.spawn()?;
    let pid = child.id();
    tracing::info!("Start rclone[{pid:?}]");

    let mut in_stream = child.stdin.take();
    let out_stream = child.stdout.take();
    let mut err_stream = child.stderr.take();

    tokio::spawn(async move {
        // Read out_stream to buffers, log one line if '\n' is encountered.
        if let Some(out_stream) = out_stream {
            read_and_log(out_stream, pid, false).await
        }
    });

    if !args.no_stdin_password {
        // Read rclone password prompt and the read password from freedesktop secret service
        match (in_stream.as_mut(), err_stream.as_mut()) {
            (Some(in_stream), Some(err_stream)) => {
                let password = password_entry.get_password().await?;
                time::timeout(Duration::from_secs(10), expect(err_stream, pid))
                    .await
                    .context("Timeout of waiting `password:`")?
                    .context("Error reading `password:` from rclone err stream")?;
                in_stream.write_all(&password.0).await?;
                in_stream.flush().await?;
            }
            _ => {
                tracing::error!(
                    "no_stdin_password is not set, but we can't get streams: in[{}], err[{}]",
                    in_stream.is_some(),
                    err_stream.is_some()
                );
            }
        }
    }

    tokio::spawn(async move {
        // Read err_stream to buffers, log one line if '\n' is encountered.
        if let Some(err_stream) = err_stream {
            read_and_log(err_stream, pid, true).await
        }
    });

    Ok(RcloneProcess::new(child))
}

/// Each time the system is going to sleep, we umount the entry.
async fn start_sleep_listener(tx: UnboundedSender<Event>) {
    async fn try_start_sleep_listener(tx: UnboundedSender<Event>) -> Result<()> {
        let connection = Connection::system().await?;
        let login_service = FdoLoginServiceProxy::new(&connection).await?;
        let mut stream = login_service.receive_prepare_for_sleep().await?;
        while let Some(signal) = stream.next().await {
            match signal.args() {
                Ok(args) => {
                    if args.prepare_for_sleep {
                        tracing::info!("About to sleep, umount");
                        // Error means the main loop has exited, there is no need to restart this
                        // listener
                        if let Err(_) = tx.send(Event::Unmount) {
                            return Ok(());
                        };
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to retrieve arguments of prepare_for_sleep signal: {e:#?}"
                    );
                    break;
                }
            }
        }
        tracing::warn!("Sleep listener exits, start a new one");
        let _ = tx.send(Event::StartSleepListener);
        Ok(())
    }

    if let Err(e) = try_start_sleep_listener(tx.clone()).await {
        tracing::error!("Sleep listener error: {e:#?}");
        let _ = tx.send(Event::Error);
    }
}

/// Since there is no resume signal, we listen to unlock signal. Each time the system unlocks, we
/// try to mount the entry.
async fn start_unlock_listener(tx: UnboundedSender<Event>) {
    async fn try_start_unlock_listener(tx: UnboundedSender<Event>) -> Result<()> {
        let connection = Connection::session().await?;
        let screen_saver_service = FdoScreenSaverServiceProxy::new(&connection).await?;
        let mut stream = screen_saver_service.receive_active_changed().await?;
        while let Some(signal) = stream.next().await {
            match signal.args() {
                Ok(args) => {
                    if !args.active {
                        tracing::info!("Unlocking, mount");
                        // Error means the main loop has exited, there is no need to restart this
                        // listener.
                        if let Err(_) = tx.send(Event::Mount) {
                            return Ok(());
                        };
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to retrieve arguments of active_changed signal: {e:#?}"
                    );
                    break;
                }
            }
        }
        tracing::warn!("Unlock listener exits, start a new one");
        let _ = tx.send(Event::StartUnlockListener);
        Ok(())
    }

    if let Err(e) = try_start_unlock_listener(tx.clone()).await {
        tracing::error!("Unlock listener error: {e:#?}");
        let _ = tx.send(Event::Error);
    }
}

async fn run(args: Args) -> Result<()> {
    fn make_sleep_than_retry_cb(tx: UnboundedSender<Event>) -> impl Fn() + Send + Clone + 'static {
        let inflight_retry_mark = Arc::new(AtomicBool::new(false));
        move || {
            if let Ok(_) = inflight_retry_mark.compare_exchange_weak(
                false,
                true,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                tokio::spawn({
                    let tx = tx.clone();
                    let inflight_retry_mark = inflight_retry_mark.clone();
                    async move {
                        let sec = 30;
                        tracing::info!("Try to mount again in {sec} seconds");
                        time::sleep(Duration::from_secs(sec)).await;
                        tracing::info!("Try to mount again");
                        let _ = tx.send(Event::Mount);
                        inflight_retry_mark.store(false, Ordering::SeqCst);
                    }
                });
            } else {
                tracing::info!("There is an inflight retry, skip");
            }
        }
    }

    init_log(args.log_timestamp)?;

    let mount_point = mount_point(&args.rclone_entry)?;
    let mut password_entry = PasswordEntry::new(args.secret_target.clone());

    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let mut child: Option<RcloneProcess> = None;
    let sleep_than_retry_cb = make_sleep_than_retry_cb(tx.clone());

    let _ = tx.send(Event::StartSleepListener);
    let _ = tx.send(Event::StartUnlockListener);
    let _ = tx.send(Event::Mount);

    while let Some(event) = rx.recv().await {
        tracing::info!("Receive a event: {event:?}");
        match event {
            Event::StartSleepListener => {
                tokio::spawn(start_sleep_listener(tx.clone()));
            }
            Event::StartUnlockListener => {
                tokio::spawn(start_unlock_listener(tx.clone()));
            }
            Event::Mount => {
                if let Some(child) = child.as_mut() {
                    if child.is_alive() {
                        continue;
                    }
                    // make sure to kill the child
                    child.close().await;
                }
                child.take();
                match mount(&args, &mount_point, &mut password_entry).await {
                    Ok(process) => {
                        process.spawn_wait_then(sleep_than_retry_cb.clone());
                        child = Some(process)
                    }
                    Err(e) => {
                        tracing::error!("Error to mount[{mount_point}], error: {e:#?}");
                        sleep_than_retry_cb();
                    }
                }
            }
            Event::Unmount => {
                if let Some(mut child) = child.take() {
                    child.close().await
                }
            }
            Event::Error => {
                tracing::error!("Error happens, exiting");
                break;
            }
        }
    }
    if let Some(mut child) = child {
        tracing::info!("Exit, killing rclone");
        child.close().await
    }

    tracing::info!("Exit");

    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("Error: {e:#?}");
        process::exit(-1);
    }
}
