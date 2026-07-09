// SPDX-License-Identifier: MIT

//! Center panel: TLS 1.3 handshake flow diagram.
//!
//! Renders a Client ↔ Server diagram with numbered steps and directional
//! arrows that mirror the canonical TLS 1.3 handshake illustration:
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

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::HandshakeStage;
use crate::ui::app::App;
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
const fn step_meta(stage: HandshakeStage) -> (u8, FlowDir, bool) {
    match stage {
        HandshakeStage::ClientHello    => (1, FlowDir::Right, false),
        HandshakeStage::ServerHello    => (2, FlowDir::Left,  false),
        HandshakeStage::Certificate    => (3, FlowDir::Left,  true),
        HandshakeStage::ClientFinished => (4, FlowDir::Right, true),
        HandshakeStage::ServerFinished => (5, FlowDir::Left,  true),
        HandshakeStage::ApplicationData => (6, FlowDir::Both, true),
        _ => (0, FlowDir::Right, false),
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
        _ => '○',
    }
}

/// Render the center handshake-flow panel.
pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let current_stage = app
        .selected()
        .map_or(HandshakeStage::Idle, |c| c.handshake.stage);

    // inner_width subtracts the 1-char borders on each side.
    let inner_width = area.width.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();

    // Header row: CLIENT … SERVER
    lines.push(header_line(inner_width));
    lines.push(connector_line(inner_width));

    // Step rows
    let ordered = HandshakeStage::ordered();
    for (i, &stage) in ordered.iter().enumerate() {
        let is_active = stage == current_stage;
        let is_past = stage_index(current_stage).is_some_and(|c| i < c);

        lines.push(step_line(stage, inner_width, is_active, is_past));

        if i + 1 < ordered.len() {
            lines.push(connector_line(inner_width));
        }
    }

    // Educational overlay
    if app.education() && current_stage != HandshakeStage::Idle {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Educational: {}", current_stage.label()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for chunk in explain(current_stage).split(". ") {
            if chunk.is_empty() {
                continue;
            }
            lines.push(Line::from(chunk));
        }
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Handshake"))
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
fn step_line(
    stage: HandshakeStage,
    inner_width: usize,
    is_active: bool,
    is_past: bool,
) -> Line<'static> {
    let (step_n, dir, encrypted) = step_meta(stage);

    let arrow_style = if is_active {
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
    let enc = if encrypted { 'E' } else { ' ' };

    // Left prefix (3 chars):
    //   "①  " for client-originating steps; "   " for server-originating.
    let left_prefix: String = match dir {
        FlowDir::Right | FlowDir::Both => format!("{}  ", ch),
        FlowDir::Left => "   ".to_string(),
    };

    // Right suffix (3 chars):
    //   " ②E" for server-originating; "  E" otherwise.
    let right_suffix: String = match dir {
        FlowDir::Left => format!(" {}{}", ch, enc),
        FlowDir::Right | FlowDir::Both => format!("  {}", enc),
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
    if width <= label.len().saturating_add(heads) {
        let max_label = width.saturating_sub(heads);
        let t = &label[..max_label.min(label.len())];
        return match dir {
            FlowDir::Right => format!("{}►", t),
            FlowDir::Left  => format!("◄{}", t),
            FlowDir::Both  => format!("◄{}►", t),
        };
    }

    let dash_total = width - label.len() - heads;
    let left_d  = dash_total / 2;
    let right_d = dash_total - left_d;
    let l = "─".repeat(left_d);
    let r = "─".repeat(right_d);

    match dir {
        FlowDir::Right => format!("{}{}{}►", l, label, r),
        FlowDir::Left  => format!("◄{}{}{}", l, label, r),
        FlowDir::Both  => format!("◄{}{}{}►", l, label, r),
    }
}

fn stage_index(stage: HandshakeStage) -> Option<usize> {
    HandshakeStage::ordered().iter().position(|s| *s == stage)
}
