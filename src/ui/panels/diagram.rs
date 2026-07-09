// SPDX-License-Identifier: MIT

//! Reference diagram overlay — shown when the user presses `[d]`.
//!
//! Renders a full-screen side-by-side ASCII comparison of the TLS 1.2 and
//! TLS 1.3 handshake flows, matching the canonical reference diagrams.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

/// Render the reference diagram overlay over the full UI area.
pub fn render(f: &mut Frame<'_>, area: Rect) {
    // Clear the background first.
    f.render_widget(Clear, area);

    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" TLS Handshake Reference  [d] close ");
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    // Split inner area into left (TLS 1.2) and right (TLS 1.3) columns.
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(inner);

    f.render_widget(tls12_widget(), cols[0]);
    f.render_widget(tls13_widget(), cols[1]);
}

// ── TLS 1.2 diagram ──────────────────────────────────────────────────────────

fn tls12_widget() -> Paragraph<'static> {
    let h = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let arrow = Style::default().fg(Color::Cyan);
    let enc = Style::default().fg(Color::Magenta);
    let bar = Style::default().fg(Color::DarkGray);
    let note = Style::default().fg(Color::DarkGray);

    let b = |s: &'static str| Span::styled(s, bar);
    let a = |s: &'static str| Span::styled(s, arrow);
    let e = |s: &'static str| Span::styled(s, enc);
    let n = |s: &'static str| Span::styled(s, note);

    let lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("CLIENT", h),
            Span::raw("                    "),
            Span::styled("SERVER", h),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ① ClientHello
        Line::from(vec![
            a("① ├──── ClientHello ─────────►│"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ② ServerHello
        Line::from(vec![
            a("  │◄──── ServerHello ──────────┤"), Span::raw(" ②"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ③ ServerCertificate (plaintext)
        Line::from(vec![
            a("  │◄──── ServerCert ───────────┤"), Span::raw(" ③"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ④ ServerKeyExchange (plaintext, DHE/ECDHE)
        Line::from(vec![
            a("  │◄──── SvrKeyExchange ────────┤"), Span::raw(" ④"),
            n(" (DHE)"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ⑥ ServerHelloDone (plaintext)
        Line::from(vec![
            a("  │◄──── SvrHelloDone ──────────┤"), Span::raw(" ⑥"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ⑦ ClientKeyExchange (plaintext)
        Line::from(vec![
            a("⑦ ├──── CltKeyExchange ─────────►│"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // [ChangeCipherSpec from client — not tracked as stage]
        Line::from(vec![
            n("  ├╌╌╌╌ ChangeCipherSpec ╌╌╌╌╌►│"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ⑩ ClientFinished (encrypted)
        Line::from(vec![
            e("⑩ ├──── Clt Finished ───────────►│  E"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // [ChangeCipherSpec from server — not tracked as stage]
        Line::from(vec![
            n("  │◄╌╌╌╌ ChangeCipherSpec ╌╌╌╌╌╌┤"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ⑫ ServerFinished (encrypted)
        Line::from(vec![
            e("  │◄──── Svr Finished ───────────┤"), e(" ⑫E"),
        ]),
        Line::from(vec![b("  │                          │")]),
        // ⑬ Application Data (encrypted)
        Line::from(vec![
            e("⑬ ├◄─── App Data ──────────────►│  E"),
        ]),
        Line::from(vec![b("  │                          │")]),
    ];

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::RIGHT)
            .title("TLS 1.2  (Full Handshake)"),
    )
}

// ── TLS 1.3 diagram ──────────────────────────────────────────────────────────

fn tls13_widget() -> Paragraph<'static> {
    let h = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let arrow = Style::default().fg(Color::Cyan);
    let enc = Style::default().fg(Color::Magenta);
    let bar = Style::default().fg(Color::DarkGray);

    let b = |s: &'static str| Span::styled(s, bar);
    let a = |s: &'static str| Span::styled(s, arrow);
    let e = |s: &'static str| Span::styled(s, enc);

    let lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("CLIENT", h),
            Span::raw("              "),
            Span::styled("SERVER", h),
        ]),
        Line::from(vec![b("  │                    │")]),
        // ① ClientHello
        Line::from(vec![
            a("① ├── ClientHello ──────►│"),
        ]),
        Line::from(vec![b("  │                    │")]),
        // ② ServerHello
        Line::from(vec![
            a("  │◄── ServerHello ───────┤"), Span::raw(" ②"),
        ]),
        Line::from(vec![b("  │                    │")]),
        // ③ Certificate flight (encrypted)
        Line::from(vec![
            e("  │◄── Certificate ────────┤"), e(" ③E"),
        ]),
        Line::from(vec![
            e("  │   (EncExt+Cert+Verify) │"),
        ]),
        Line::from(vec![b("  │                    │")]),
        // ④ ClientFinished (encrypted)
        Line::from(vec![
            e("④ ├── Clt Finished ─────►│  E"),
        ]),
        Line::from(vec![b("  │                    │")]),
        // ⑤ ServerFinished (encrypted)
        Line::from(vec![
            e("  │◄── Svr Finished ───────┤"), e(" ⑤E"),
        ]),
        Line::from(vec![b("  │                    │")]),
        // ⑥ Application Data (encrypted)
        Line::from(vec![
            e("⑥ ├◄── App Data ──────────►│  E"),
        ]),
        Line::from(vec![b("  │                    │")]),
        // Padding lines to align with the TLS 1.2 column height.
        Line::from(""),
        Line::from(""),
        Line::from(""),
        Line::from(""),
        Line::from(""),
        Line::from(""),
        Line::from(""),
    ];

    Paragraph::new(lines)
        .block(Block::default().borders(Borders::NONE).title("TLS 1.3  (1-RTT)"))
}
