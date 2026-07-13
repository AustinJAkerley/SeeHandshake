// SPDX-License-Identifier: MIT

//! Terminal user interface (Ratatui + crossterm).
//!
//! The UI is organized as a three-panel layout — connections on the left,
//! animated handshake flow in the center, negotiated metadata on the
//! right — driven by an [`app::App`] state machine that receives updates
//! from the parser/tracker thread via an `mpsc::Receiver`.

pub mod app;
pub mod education;
pub mod event;
pub mod panels;
pub mod sections;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossterm::event::{self as ct_event, Event as CtEvent, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::capture::{extract_tcp, LivePcapSource, PacketSource};
use crate::cli::Args;
use crate::error::Result;
use crate::model::connection::Direction;
use crate::model::ConnectionKey;
use crate::tracker::{unix_now_ms, ConnectionTracker};
use crate::ui::app::App;
use crate::ui::event::UiEvent;

/// Run the live UI end-to-end.
///
/// Spawns:
///
/// 1. A capture thread that owns a [`LivePcapSource`] and forwards
///    [`crate::capture::Frame`] values into a bounded channel.
/// 2. A parser+tracker thread that consumes those frames, feeds them
///    through [`ConnectionTracker`], and emits [`UiEvent`] updates.
///
/// The calling thread becomes the UI thread: it drives the Ratatui event
/// loop and services keyboard input until the user quits.
///
/// # Errors
///
/// Returns any error surfaced by the capture backend, the tracker, or the
/// terminal.
pub fn run_live(args: &Args) -> Result<()> {
    let (frame_tx, frame_rx) = mpsc::channel::<crate::capture::Frame>();
    let (ui_tx, ui_rx) = mpsc::channel::<UiEvent>();

    let bpf = args.bpf.clone();
    let iface = args.interface.clone();

    let shutdown = Arc::new(AtomicBool::new(false));

    // Capture thread ---------------------------------------------------------
    let capture_shutdown = Arc::clone(&shutdown);
    let capture_handle = thread::Builder::new()
        .name("seehandshake-capture".into())
        .spawn(move || {
            let source = match iface {
                Some(name) => LivePcapSource::open(&name, &bpf),
                None => LivePcapSource::open_default(&bpf),
            };
            let mut source = match source {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("capture: {e}");
                    return;
                }
            };
            loop {
                if capture_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                match source.next_frame() {
                    Ok(Some(frame)) => {
                        if frame_tx.send(frame).is_err() {
                            break; // receiver hung up.
                        }
                    }
                    Ok(None) => {
                        // Timeout or EOF; loop back to check the shutdown flag.
                    }
                    Err(e) => {
                        tracing::error!("capture: {e}");
                        break;
                    }
                }
            }
        })
        .map_err(|e| crate::Error::Ui(format!("failed to spawn capture thread: {e}")))?;

    // Parser + tracker thread ------------------------------------------------
    let tracker_ui_tx = ui_tx.clone();
    let tracker_handle = thread::Builder::new()
        .name("seehandshake-tracker".into())
        .spawn(move || {
            let mut tracker = ConnectionTracker::new();
            for frame in frame_rx {
                let Some(seg) = extract_tcp(&frame.bytes) else {
                    continue;
                };
                let key =
                    ConnectionKey::canonical(seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port);
                let direction = if (seg.src_ip, seg.src_port) == (key.client_ip, key.client_port) {
                    Direction::ClientToServer
                } else {
                    Direction::ServerToClient
                };
                let endpoint_a = std::net::SocketAddr::new(seg.src_ip, seg.src_port);
                let endpoint_b = std::net::SocketAddr::new(seg.dst_ip, seg.dst_port);
                let now = unix_now_ms();
                match tracker.ingest(key, direction, endpoint_a, endpoint_b, seg.payload, now) {
                    Ok(Some(state)) => {
                        if tracker_ui_tx
                            .send(UiEvent::HandshakeUpdated(Box::new(state)))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!("tracker: {e}"),
                }
                // Periodic eviction — cheap; runs every batch.
                let removed = tracker.evict_stale(now);
                if removed > 0 {
                    let _ = tracker_ui_tx.send(UiEvent::StaleEvicted(removed));
                }
            }
        })
        .map_err(|e| crate::Error::Ui(format!("failed to spawn tracker thread: {e}")))?;

    // Terminal setup ---------------------------------------------------------
    enable_raw_mode().map_err(|e| crate::Error::Ui(e.to_string()))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| crate::Error::Ui(e.to_string()))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| crate::Error::Ui(e.to_string()))?;

    let outcome = run_event_loop(&mut terminal, &ui_rx);

    // Terminal teardown ------------------------------------------------------
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    // Signal shutdown to helper threads. The capture thread checks the
    // atomic between pcap polls (so it exits on the next 100ms timeout even
    // on an idle interface); once it drops `frame_tx`, the tracker thread's
    // `for frame in frame_rx` loop terminates naturally.
    shutdown.store(true, Ordering::Relaxed);
    drop(ui_tx);
    let _ = capture_handle.join();
    let _ = tracker_handle.join();

    outcome.map_err(|e| crate::Error::Ui(format!("running the UI event loop: {e}")))
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ui_rx: &mpsc::Receiver<UiEvent>,
) -> Result<()> {
    let mut app = App::new();
    let tick = Duration::from_millis(150);
    loop {
        // Drain pending updates without blocking.
        while let Ok(evt) = ui_rx.try_recv() {
            app.handle_ui_event(evt);
        }

        terminal
            .draw(|f| panels::render(f, &app))
            .map_err(|e| crate::Error::Ui(e.to_string()))?;

        if ct_event::poll(tick).map_err(|e| crate::Error::Ui(e.to_string()))? {
            if let CtEvent::Key(key) =
                ct_event::read().map_err(|e| crate::Error::Ui(e.to_string()))?
            {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('w') => app.clear_connections(),
                    KeyCode::Esc | KeyCode::Left => app.focus_left(),
                    KeyCode::Char('e') => app.toggle_education(),
                    KeyCode::Char('d') => app.toggle_diagram(),
                    KeyCode::Char('f') => app.toggle_middle_mode(),
                    KeyCode::Enter | KeyCode::Right => app.focus_right(),
                    KeyCode::Tab => app.focus_cycle(),
                    KeyCode::Up => app.select_prev(),
                    KeyCode::Down => app.select_next(),
                    _ => {}
                }
            }
        }

        app.tick();
    }
    Ok(())
}
