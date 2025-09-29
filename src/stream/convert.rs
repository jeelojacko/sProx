use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStderr, ChildStdout, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const STDERR_CAPTURE_LIMIT: usize = 64 * 1024;

/// User-facing error emitted when streaming conversion output fails.
#[derive(Debug, Clone)]
pub struct ConversionStreamError {
    message: String,
}

impl ConversionStreamError {
    /// Constructs a new [`ConversionStreamError`] with the provided message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the message associated with the streaming error.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Errors surfaced when managing the external packager process.
#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("failed to spawn packager `{program}`: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to capture stdout for `{program}`")]
    MissingStdout { program: String },
    #[error("failed to capture stderr for `{program}`")]
    MissingStderr { program: String },
    #[error("failed to read stdout from `{program}`: {source}")]
    ReadStdout {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read stderr from `{program}`: {source}")]
    ReadStderr {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to wait for `{program}`: {source}")]
    Wait {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("packager task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("conversion process `{program}` exited with status {status}: {stderr}")]
    ProcessFailed {
        program: String,
        status: i32,
        stderr: String,
        stderr_truncated: bool,
    },
    #[error("conversion process `{program}` terminated by signal")]
    ProcessTerminated { program: String },
}

/// High-level description of the completed conversion invocation.
#[derive(Debug, Clone)]
pub struct ConversionSummary {
    program: String,
    args: Vec<String>,
    success: bool,
    exit_code: Option<i32>,
    stderr: String,
    stderr_truncated: bool,
}

impl ConversionSummary {
    /// Name of the external program that executed the conversion.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Arguments passed to the external program.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Returns whether the process completed successfully.
    pub fn success(&self) -> bool {
        self.success
    }

    /// Returns the exit code reported by the process, when available.
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Captured stderr output (truncated to a reasonable size).
    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    /// Indicates whether the captured stderr output was truncated.
    pub fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }
}

/// Handle representing the running packager invocation.
#[derive(Debug)]
pub struct ConversionHandle {
    program: String,
    args: Vec<String>,
    receiver: mpsc::Receiver<Result<Vec<u8>, ConversionStreamError>>,
    completion: JoinHandle<Result<ConversionSummary, ConversionError>>,
}

impl ConversionHandle {
    /// Returns the program associated with this conversion.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Returns the arguments that were passed to the program.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Waits for the packager to exit and returns the conversion summary.
    pub async fn wait(self) -> Result<ConversionSummary, ConversionError> {
        self.completion.await?
    }
}

impl Stream for ConversionHandle {
    type Item = Result<Vec<u8>, ConversionStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_recv(cx)
    }
}

/// Builder describing an external packager invocation.
#[derive(Debug, Clone)]
pub struct PackagerCommand {
    program: OsString,
    args: Vec<OsString>,
    env: HashMap<OsString, OsString>,
    current_dir: Option<PathBuf>,
}

impl PackagerCommand {
    /// Creates a new [`PackagerCommand`] using the provided program path.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: HashMap::new(),
            current_dir: None,
        }
    }

    /// Adds a single argument to the invocation.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Extends the invocation with multiple arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Adds an environment variable to the invocation.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Sets the working directory for the invocation.
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }

    fn build(self) -> (String, Vec<String>, Command) {
        let program_display = self.program.to_string_lossy().into_owned();
        let args_display = self
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        let mut command = Command::new(&self.program);
        command.args(&self.args);
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
        command.kill_on_drop(true);

        if let Some(dir) = self.current_dir {
            command.current_dir(dir);
        }

        for (key, value) in self.env {
            command.env(key, value);
        }

        (program_display, args_display, command)
    }
}

/// Spawns an FFmpeg or Shaka Packager process and streams stdout asynchronously.
pub async fn spawn_packager(command: PackagerCommand) -> Result<ConversionHandle, ConversionError> {
    let (program, args, mut command) = command.build();
    let program_for_stdout = program.clone();
    let program_for_stderr = program.clone();
    let program_for_wait = program.clone();
    let args_for_wait = args.clone();

    let mut child = command.spawn().map_err(|source| ConversionError::Spawn {
        program: program.clone(),
        source,
    })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ConversionError::MissingStdout {
            program: program.clone(),
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ConversionError::MissingStderr {
            program: program.clone(),
        })?;

    let (sender, receiver) = mpsc::channel(32);

    let stdout_handle = tokio::spawn(forward_stdout(stdout, program_for_stdout, sender));
    let stderr_handle = tokio::spawn(capture_stderr(stderr, program_for_stderr));

    let completion = tokio::spawn(async move {
        let status = child.wait().await.map_err(|source| ConversionError::Wait {
            program: program_for_wait.clone(),
            source,
        })?;

        stdout_handle.await??;

        let (stderr_output, stderr_truncated) = stderr_handle.await??;

        if !status.success() {
            if let Some(code) = status.code() {
                return Err(ConversionError::ProcessFailed {
                    program: program_for_wait.clone(),
                    status: code,
                    stderr: stderr_output,
                    stderr_truncated,
                });
            } else {
                return Err(ConversionError::ProcessTerminated {
                    program: program_for_wait.clone(),
                });
            }
        }

        Ok(ConversionSummary {
            program: program_for_wait,
            args: args_for_wait,
            success: true,
            exit_code: status.code(),
            stderr: stderr_output,
            stderr_truncated,
        })
    });

    Ok(ConversionHandle {
        program,
        args,
        receiver,
        completion,
    })
}

async fn forward_stdout(
    stdout: ChildStdout,
    program: String,
    sender: mpsc::Sender<Result<Vec<u8>, ConversionStreamError>>,
) -> Result<(), ConversionError> {
    let mut reader = BufReader::new(stdout);

    loop {
        let mut buffer = Vec::with_capacity(1024);
        let read_result = reader.read_until(b'\n', &mut buffer).await;
        match read_result {
            Ok(0) => break,
            Ok(_) => {
                if sender.send(Ok(buffer)).await.is_err() {
                    break;
                }
            }
            Err(err) => {
                let message = err.to_string();
                let _ = sender.send(Err(ConversionStreamError::new(message))).await;
                return Err(ConversionError::ReadStdout {
                    program,
                    source: err,
                });
            }
        }
    }

    drop(sender);
    Ok(())
}

async fn capture_stderr(
    stderr: ChildStderr,
    program: String,
) -> Result<(String, bool), ConversionError> {
    let mut reader = BufReader::new(stderr);
    let mut line = String::new();
    let mut captured = String::new();
    let mut truncated = false;

    loop {
        line.clear();
        let bytes_read =
            reader
                .read_line(&mut line)
                .await
                .map_err(|source| ConversionError::ReadStderr {
                    program: program.clone(),
                    source,
                })?;

        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        log_stderr_line(&program, trimmed);
        append_captured_line(trimmed, &mut captured, &mut truncated);
    }

    Ok((captured, truncated))
}

fn append_captured_line(line: &str, captured: &mut String, truncated: &mut bool) {
    if *truncated || line.is_empty() {
        return;
    }

    if !captured.is_empty() {
        if captured.len() + 1 >= STDERR_CAPTURE_LIMIT {
            *truncated = true;
            return;
        }
        captured.push('\n');
    }

    let remaining = STDERR_CAPTURE_LIMIT.saturating_sub(captured.len());
    if remaining == 0 {
        *truncated = true;
        return;
    }

    if line.len() <= remaining {
        captured.push_str(line);
    } else {
        let truncated_line = truncate_to_boundary(line, remaining);
        captured.push_str(truncated_line);
        *truncated = true;
    }
}

fn truncate_to_boundary(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }

    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn log_stderr_line(program: &str, line: &str) {
    #[cfg(feature = "telemetry")]
    tracing::warn!(target = "sprox::packager", %program, %line, "packager stderr");
    #[cfg(not(feature = "telemetry"))]
    {
        let _ = (program, line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn packager_stdout_is_streamed() {
        let command = PackagerCommand::new("sh")
            .arg("-c")
            .arg("printf 'first\\nsecond'");

        let mut handle = spawn_packager(command).await.expect("spawn");
        let mut chunks = Vec::new();
        while let Some(item) = handle.next().await {
            let data = item.expect("stream error");
            chunks.push(String::from_utf8(data).expect("utf8"));
        }

        assert_eq!(chunks, vec!["first\n".to_string(), "second".to_string()]);

        let summary = handle.wait().await.expect("summary");
        assert!(summary.success());
        assert_eq!(summary.exit_code(), Some(0));
        assert!(summary.stderr().is_empty());
        assert!(!summary.stderr_truncated());
    }

    #[tokio::test]
    async fn packager_failures_are_reported() {
        let command = PackagerCommand::new("sh")
            .arg("-c")
            .arg("echo boom >&2; exit 3");

        let mut handle = spawn_packager(command).await.expect("spawn");
        while let Some(_chunk) = handle.next().await {}

        let error = handle.wait().await.expect_err("should fail");
        match error {
            ConversionError::ProcessFailed {
                status,
                stderr,
                stderr_truncated,
                ..
            } => {
                assert_eq!(status, 3);
                assert!(stderr.contains("boom"));
                assert!(!stderr_truncated);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
