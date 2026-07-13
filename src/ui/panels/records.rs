// SPDX-License-Identifier: MIT

//! Middle panel: TLS record timeline for the currently selected connection.
//!
//! A short connection-summary header (SNI, TLS version, cipher, key
//! group) sits above the record list. The list itself is one row per
//! observed record; arrow keys move the selection when this pane is
//! focused.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::record::{RecordBody, RecordDirection, RecordEvent};
use crate::model::tls::TlsVersion;
use crate::ui::app::{App, PaneFocus};

/// Render the records panel.
pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let focused = app.focus() == PaneFocus::Records;

    let title = if focused {
        "Handshake [focus]"
    } else {
        "Handshake"
    };
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(state) = app.selected() else {
        let p = Paragraph::new(vec![Line::from(Span::styled(
            "No connection selected.",
            Style::default().fg(Color::DarkGray),
        ))])
        .wrap(Wrap { trim: false });
        f.render_widget(p, inner);
        return;
    };

    let header_lines = summary_header(state);
    let header_h = u16::try_from(header_lines.len().min(inner.height as usize)).unwrap_or(0);

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(header_h), Constraint::Min(0)])
        .split(inner);

    if header_h > 0 {
        f.render_widget(
            Paragraph::new(header_lines).wrap(Wrap { trim: false }),
            split[0],
        );
    }

    let first_ts = state.records.first().map(|r| r.timestamp_ms).unwrap_or(0);
    let mut items: Vec<ListItem> = Vec::with_capacity(state.records.len() + 1);
    items.push(ListItem::new(metadata_row_line()));
    items.extend(
        state
            .records
            .iter()
            .map(|r| ListItem::new(row_line(r, first_ts))),
    );

    let mut list_state = ListState::default();
    list_state.select(Some(app.records_row().min(items.len() - 1)));

    let list = List::new(items)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("\u{25B6} ");
    f.render_stateful_widget(list, split[1], &mut list_state);
}

fn summary_header(state: &crate::model::ConnectionState) -> Vec<Line<'static>> {
    let hs = &state.handshake;
    let mut lines = Vec::new();
    let sni = hs
        .sni
        .clone()
        .unwrap_or_else(|| state.key.server_ip.to_string());
    lines.push(Line::from(vec![
        Span::styled(
            "\u{2192} ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(sni, Style::default().add_modifier(Modifier::BOLD)),
    ]));
    let mut summary = String::new();
    if let Some(v) = hs.tls_version {
        summary.push_str(&format!("{v}"));
    }
    if let Some(c) = hs.cipher_suite_selected {
        if !summary.is_empty() {
            summary.push_str("  \u{00B7}  ");
        }
        summary.push_str(&format!("{c}"));
    }
    if let Some(g) = hs.key_share_group {
        if !summary.is_empty() {
            summary.push_str("  \u{00B7}  ");
        }
        summary.push_str(&format!("{g}"));
    }
    if !summary.is_empty() {
        lines.push(Line::from(Span::styled(
            summary,
            Style::default().fg(Color::DarkGray),
        )));
    }
    // Small legend framing the handshake flights so the record list
    // reads as a protocol trace rather than a flat log.
    let legend = match hs.tls_version {
        Some(TlsVersion::Tls13) => {
            "flights:  1) ClientHello (clear)   2) ServerHello (clear)   3+) encrypted handshake"
        }
        Some(TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12) => {
            "flights:  1) ClientHello   2) ServerHello / Certificate / KeyExchange   3) CCS + encrypted Finished"
        }
        _ => "flights:  1) ClientHello (clear)   2) ServerHello (clear)   3+) protocol-dependent",
    };
    lines.push(Line::from(Span::styled(
        legend,
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    lines
}

fn row_line(r: &RecordEvent, first_ts: u64) -> Line<'static> {
    let dt = r.timestamp_ms.saturating_sub(first_ts);
    let arrow = r.direction.arrow();
    let dir_color = match r.direction {
        RecordDirection::ClientToServer => Color::Green,
        RecordDirection::ServerToClient => Color::Magenta,
    };
    let dir_style = Style::default().fg(dir_color);
    let (tag, _tag_color, label) = describe(r);
    Line::from(vec![
        Span::styled(format!("{arrow} "), dir_style.add_modifier(Modifier::BOLD)),
        Span::styled(format!("{dt:>5}ms  "), dir_style),
        Span::styled(format!("{tag:<11}"), dir_style),
        Span::styled(format!("{:>5}B  ", r.outer_length), dir_style),
        Span::styled(label, dir_style),
    ])
}

/// The synthetic first row of the records list. Selecting it flips the
/// right pane back to connection-summary metadata — the only way to
/// return to that view without switching connections.
fn metadata_row_line() -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::raw("         "),
        Span::styled(
            format!("{:<11}", "Metadata"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("        "),
        Span::styled("connection overview", Style::default().fg(Color::DarkGray)),
    ])
}

fn describe(r: &RecordEvent) -> (&'static str, Color, String) {
    match &r.body {
        RecordBody::Handshake(hs) => ("plaintext", Color::Yellow, hs.label().to_string()),
        RecordBody::EncryptedHandshake { inferred_label, .. } => {
            ("encrypted", Color::Blue, (*inferred_label).to_string())
        }
        RecordBody::ChangeCipherSpec => (
            "legacy",
            Color::DarkGray,
            "ChangeCipherSpec (cipher activation)".to_string(),
        ),
    }
}
