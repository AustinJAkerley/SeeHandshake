// SPDX-License-Identifier: MIT

//! Right panel: negotiated metadata for the currently selected connection.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::HandshakeInfo;
use crate::ui::app::App;

/// Render the metadata panel.
pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let mut lines = Vec::new();
    if let Some(state) = app.selected() {
        lines.push(field("Connection", state.key.to_string()));
        for line in metadata_lines(&state.handshake) {
            lines.push(line);
        }
        if let Some(err) = &state.handshake.error {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("Error: {err}"),
                Style::default().fg(Color::Red),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No connection selected. Waiting for traffic\u{2026}",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Metadata"))
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn metadata_lines(hs: &HandshakeInfo) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(field(
        "TLS Version",
        hs.tls_version
            .map_or_else(|| "\u{2014}".to_string(), |v| v.to_string()),
    ));
    lines.push(field(
        "SNI",
        hs.sni.clone().unwrap_or_else(|| "\u{2014}".into()),
    ));
    lines.push(field(
        "Cipher",
        hs.cipher_suite_selected
            .map_or_else(|| "\u{2014}".to_string(), |c| c.to_string()),
    ));
    lines.push(field(
        "Key Exchange",
        hs.key_share_group
            .map_or_else(|| "\u{2014}".to_string(), |g| g.to_string()),
    ));
    lines.push(field(
        "ALPN offered",
        if hs.alpn_offered.is_empty() {
            "\u{2014}".into()
        } else {
            hs.alpn_offered
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        },
    ));
    lines.push(field(
        "ALPN selected",
        hs.alpn_selected
            .clone()
            .map_or_else(|| "encrypted (TLS 1.3)".to_string(), |a| a.to_string()),
    ));
    lines.push(field(
        "Cert Subject",
        hs.certificate_subject
            .clone()
            .unwrap_or_else(|| "\u{2014}".into()),
    ));
    lines.push(field(
        "Cert Issuer",
        hs.certificate_issuer
            .clone()
            .unwrap_or_else(|| "\u{2014}".into()),
    ));

    lines
}

fn field(label: &'static str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<16}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value),
    ])
}
