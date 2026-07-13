// SPDX-License-Identifier: MIT

//! Center panel: TLS handshake flow diagram (version-aware).
//!
//! Renders a Client ↔ Server diagram with numbered steps and directional
//! arrows. For TLS 1.3 the layout mirrors the 6-step diagram:
//!
//! ```text
//!  CLIENT              SERVER
//!    │                    │
//! ①  │─── ClientHello ────►│
//!    │                    │
//!    │◄─── ServerHello ────│ ②
//!    │                    │
//!    │◄─── Certificate ────│ ③E
//!    │                    │
//! ④  │─── Clt Finished ───►│  E
//!    │                    │
//!    │◄─── Svr Finished ───│ ⑤E
//!    │                    │
//! ⑥  │◄─── App Data ──────►│  E
//!    │                    │
//! ```
//!
//! For TLS 1.2 the layout uses the 9-step diagram (skipping optional steps
//! and ChangeCipherSpec rows which are not tracked as stages):
//!
//! ```text
//!  CLIENT              SERVER
//!    │                    │
//! ①  │─── ClientHello ────►│
//!    │                    │
//!    │◄─── ServerHello ────│ ②
//!    │                    │
//!    │◄─── Server Cert ────│ ③
//!    │                    │
//!    │◄─── Svr Key Exch ───│ ④
//!    │                    │
//!    │◄─── Svr Hello Done─ │ ⑥
//!    │                    │
//! ⑦  │─── Clt Key Exch ───►│
//!    │                    │
//! ⑩  │─── Clt Finished ───►│  E
//!    │                    │
//!    │◄─── Svr Finished ───│ ⑫E
//!    │                    │
//! ⑬  │◄─── App Data ──────►│  E
//!    │                    │
//! ```

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::tls::TlsVersion;
use crate::model::HandshakeStage;
use crate::ui::app::{App, PaneFocus};
use crate::ui::education::explain;

/// Direction a handshake message travels on the wire.
#[derive(Clone, Copy)]
enum FlowDir {
    /// Client → Server.
    Right,
    /// Server → Client.
    Left,
    /// Bidirectional (application data).
    Both,
}

/// Per-stage diagram metadata: `(step_number, direction, is_encrypted)`.
///
/// `is_tls12` selects the step number for shared stages that differ between
/// TLS 1.2 (ClientFinished = ⑩, ServerFinished = ⑫, ApplicationData = ⑬)
/// and TLS 1.3 (④, ⑤, ⑥).
fn step_meta(stage: HandshakeStage, is_tls12: bool) -> (u8, FlowDir, bool) {
    match stage {
        HandshakeStage::ClientHello => (1, FlowDir::Right, false),
        HandshakeStage::ServerHello => (2, FlowDir::Left, false),
        HandshakeStage::Certificate => (3, FlowDir::Left, true), // TLS 1.3
        HandshakeStage::ServerCertificate => (3, FlowDir::Left, false), // TLS 1.2
        HandshakeStage::ServerKeyExchange => (4, FlowDir::Left, false), // TLS 1.2
        HandshakeStage::ServerHelloDone => (6, FlowDir::Left, false), // TLS 1.2
        HandshakeStage::ClientKeyExchange => (7, FlowDir::Right, false), // TLS 1.2
        HandshakeStage::ClientFinished => {
            if is_tls12 {
                (10, FlowDir::Right, true)
            } else {
                (4, FlowDir::Right, true)
            }
        }
        HandshakeStage::ServerFinished => {
            if is_tls12 {
                (12, FlowDir::Left, true)
            } else {
                (5, FlowDir::Left, true)
            }
        }
        HandshakeStage::ApplicationData => {
            if is_tls12 {
                (13, FlowDir::Both, true)
            } else {
                (6, FlowDir::Both, true)
            }
        }
        // Idle and Errored are never rendered as step rows.
        HandshakeStage::Idle | HandshakeStage::Errored => (0, FlowDir::Right, false),
    }
}

fn circled(n: u8) -> char {
    match n {
        1 => '①',
        2 => '②',
        3 => '③',
        4 => '④',
        5 => '⑤',
        6 => '⑥',
        7 => '⑦',
        8 => '⑧',
        9 => '⑨',
        10 => '⑩',
        11 => '⑪',
        12 => '⑫',
        13 => '⑬',
        _ => '○',
    }
}

/// Render the center handshake-flow panel.
pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let selected = app.selected();
    let current_stage = selected.map_or(HandshakeStage::Idle, |c| c.handshake.stage);

    let is_tls12 = selected
        .and_then(|c| c.handshake.tls_version)
        .is_some_and(|v| {
            matches!(
                v,
                TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12
            )
        });

    // inner_width subtracts the 1-char borders on each side.
    let inner_width = area.width.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();

    // Header row: CLIENT … SERVER
    lines.push(header_line(inner_width));
    lines.push(connector_line(inner_width));

    // Step rows
    let ordered = if is_tls12 {
        HandshakeStage::ordered_tls12()
    } else {
        HandshakeStage::ordered()
    };
    // The Flow view's cursor is derived from the middle-pane record
    // selection so ↑/↓ walks the same underlying list. The diagram is
    // just a graphical rendering of the record timeline.
    let cursor_stage = app.selected_record_stage();
    let cursor_idx = cursor_stage.and_then(|s| ordered.iter().position(|o| *o == s));
    let current_idx = ordered.iter().position(|s| *s == current_stage);
    for (i, &stage) in ordered.iter().enumerate() {
        let is_cursor = cursor_idx == Some(i);
        let is_current = current_idx == Some(i);
        let is_past = current_idx.is_some_and(|c| i < c);

        lines.push(step_line(
            stage,
            inner_width,
            is_cursor,
            is_current,
            is_past,
            is_tls12,
        ));

        if i + 1 < ordered.len() {
            lines.push(connector_line(inner_width));
        }
    }

    // Educational overlay keyed to the cursor stage (falls back to the
    // tracker's current stage when the user is parked on the Metadata
    // pseudo-row).
    let focused_stage = cursor_stage.unwrap_or(current_stage);
    if app.education() && focused_stage != HandshakeStage::Idle {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Educational: {}", focused_stage.label()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for chunk in explain(focused_stage).split(". ") {
            if chunk.is_empty() {
                continue;
            }
            lines.push(Line::from(chunk));
        }
    }

    let focused = app.focus() == PaneFocus::Records;
    let base_title = if is_tls12 {
        "Handshake (TLS 1.2)"
    } else {
        "Handshake"
    };
    let title = if focused {
        format!("{base_title} [focus]")
    } else {
        base_title.to_string()
    };
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

// ── Layout ───────────────────────────────────────────────────────────────────
//
// Each row occupies inner_width columns split as:
//   [3 chars left prefix][│][content_width chars][│][3 chars right suffix]
//   = inner_width
//   → content_width = inner_width − 8

fn cw(inner_width: usize) -> usize {
    inner_width.saturating_sub(8)
}

/// "CLIENT … SERVER" header row.
fn header_line(inner_width: usize) -> Line<'static> {
    let bold_yellow = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let bar = Style::default().fg(Color::DarkGray);

    let content_w = cw(inner_width);
    let left_label = "CLIENT";
    let right_label = "SERVER";
    let gap = content_w.saturating_sub(left_label.len() + right_label.len());

    Line::from(vec![
        Span::raw("   "),
        Span::styled("│", bar),
        Span::styled(left_label, bold_yellow),
        Span::raw(" ".repeat(gap)),
        Span::styled(right_label, bold_yellow),
        Span::styled("│", bar),
        Span::raw("   "),
    ])
}

/// Blank connector row showing only the two vertical bars.
fn connector_line(inner_width: usize) -> Line<'static> {
    let bar = Style::default().fg(Color::DarkGray);
    Line::from(vec![
        Span::raw("   "),
        Span::styled("│", bar),
        Span::raw(" ".repeat(cw(inner_width))),
        Span::styled("│", bar),
        Span::raw("   "),
    ])
}

/// A single step row with directional arrow and step annotation.
///
/// `is_cursor` is the user's selection cursor within the diagram (moved by
/// arrow keys); `is_current` is the connection's actually-reached stage
/// (from the tracker). They are usually different. For example, the user
/// can arrow up to inspect ClientHello even after ApplicationData has been
/// reached.
fn step_line(
    stage: HandshakeStage,
    inner_width: usize,
    is_cursor: bool,
    is_current: bool,
    is_past: bool,
    is_tls12: bool,
) -> Line<'static> {
    let (step_n, dir, encrypted) = step_meta(stage, is_tls12);

    let arrow_style = if is_cursor {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD | Modifier::REVERSED)
    } else if is_current {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else if is_past {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    };
    let bar = Style::default().fg(Color::DarkGray);

    let ch = circled(step_n);

    // Left prefix (3 display columns):
    //   "①  " for client-originating steps; "   " for server-originating.
    let left_prefix: String = match dir {
        FlowDir::Right | FlowDir::Both => format!("{ch}  "),
        FlowDir::Left => "   ".into(),
    };

    // Right suffix (3 display columns):
    //   " ②E" for server-originating; "  E" or "   " otherwise.
    let right_suffix: String = match dir {
        FlowDir::Left => format!(" {ch}{}", if encrypted { 'E' } else { ' ' }),
        FlowDir::Right | FlowDir::Both => {
            if encrypted {
                "  E".into()
            } else {
                "   ".into()
            }
        }
    };

    let content_w = cw(inner_width);
    let arrow = make_arrow(dir, stage.label(), content_w);

    Line::from(vec![
        Span::styled(left_prefix, arrow_style),
        Span::styled("│", bar),
        Span::styled(arrow, arrow_style),
        Span::styled("│", bar),
        Span::styled(right_suffix, arrow_style),
    ])
}

/// Build an arrow string of exactly `width` display columns.
///
/// ```text
/// Right: "───── Label ──────────────►"
/// Left:  "◄───────────── Label ──────"
/// Both:  "◄──────── Label ───────────►"
/// ```
fn make_arrow(dir: FlowDir, label: &str, width: usize) -> String {
    let heads: usize = match dir {
        FlowDir::Both => 2,
        _ => 1,
    };

    // Insufficient space: truncate label and attach arrowhead(s).
    // When width <= label.len() + heads, max_label = width - heads <= label.len(),
    // so the slice is always in-bounds (all stage labels are ASCII).
    if width <= label.len().saturating_add(heads) {
        let max_label = width.saturating_sub(heads);
        let t = &label[..max_label];
        return match dir {
            FlowDir::Right => format!("{t}►"),
            FlowDir::Left => format!("◄{t}"),
            FlowDir::Both => format!("◄{t}►"),
        };
    }

    let dash_total = width - label.len() - heads;
    let left_d = dash_total / 2;
    let right_d = dash_total - left_d;
    let l = "─".repeat(left_d);
    let r = "─".repeat(right_d);

    match dir {
        FlowDir::Right => format!("{l}{label}{r}►"),
        FlowDir::Left => format!("◄{l}{label}{r}"),
        FlowDir::Both => format!("◄{l}{label}{r}►"),
    }
}
