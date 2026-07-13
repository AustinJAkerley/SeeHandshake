// SPDX-License-Identifier: MIT

//! Connection-level metadata rendering.
//!
//! Split from panel rendering so that the right pane can render this
//! content (in `Metadata` mode) without owning the `Block`/`Paragraph`
//! wrapping.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::model::HandshakeInfo;
use crate::origin::Origin;
use crate::ui::app::App;

/// Produce the connection-metadata lines for the currently selected
/// connection. Empty if nothing is selected.
pub(crate) fn metadata_lines(app: &App) -> Vec<Line<'static>> {
    let Some(state) = app.selected() else {
        return vec![Line::from(Span::styled(
            "No connection selected. Waiting for traffic\u{2026}",
            Style::default().fg(Color::DarkGray),
        ))];
    };

    let mut lines = Vec::new();
    lines.push(field("Connection", state.key.to_string()));
    if let Some(origin_lines) = origin_line(state.handshake.origin.as_ref()) {
        lines.extend(origin_lines);
    }
    lines.extend(handshake_metadata_lines(&state.handshake));
    if let Some(err) = &state.handshake.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    lines
}

fn handshake_metadata_lines(hs: &HandshakeInfo) -> Vec<Line<'static>> {
    vec![
        field(
            "TLS Version",
            hs.tls_version
                .map_or_else(|| "\u{2014}".to_string(), |v| v.to_string()),
        ),
        field("SNI", hs.sni.clone().unwrap_or_else(|| "\u{2014}".into())),
        field(
            "Cipher",
            hs.cipher_suite_selected
                .map_or_else(|| "\u{2014}".to_string(), |c| c.to_string()),
        ),
        field(
            "Key Exchange",
            hs.key_share_group
                .map_or_else(|| "\u{2014}".to_string(), |g| g.to_string()),
        ),
        field(
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
        ),
        field(
            "ALPN selected",
            hs.alpn_selected
                .clone()
                .map_or_else(|| "encrypted (TLS 1.3)".to_string(), |a| a.to_string()),
        ),
        field(
            "Cert Subject",
            hs.certificate_subject
                .clone()
                .unwrap_or_else(|| "\u{2014}".into()),
        ),
        field(
            "Cert Issuer",
            hs.certificate_issuer
                .clone()
                .unwrap_or_else(|| "\u{2014}".into()),
        ),
    ]
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

/// Render the "Origin" row. Returns `None` when attribution is unresolved
/// or the platform has no resolver. Omitting a row is preferable to
/// filling the panel with dash placeholders.
pub(crate) fn origin_line(origin: Option<&Origin>) -> Option<Vec<Line<'static>>> {
    let origin = origin?;
    match origin {
        Origin::Local(p) => {
            let mut out = vec![Line::from(vec![
                Span::styled(
                    format!("{:<16}", "Origin"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(p.comm.clone(), Style::default().fg(Color::Green)),
                Span::styled(
                    format!(" (pid {}, uid {})", p.pid, p.uid),
                    Style::default().fg(Color::DarkGray),
                ),
            ])];
            if !p.cmdline.is_empty() && p.cmdline != p.comm {
                out.push(Line::from(vec![
                    Span::raw(" ".repeat(16)),
                    Span::styled(p.cmdline.clone(), Style::default().fg(Color::DarkGray)),
                ]));
            }
            Some(out)
        }
        Origin::OtherUser { uid } => Some(vec![Line::from(vec![
            Span::styled(
                format!("{:<16}", "Origin"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("other user (uid {uid})"),
                Style::default().fg(Color::DarkGray),
            ),
        ])]),
        Origin::Unknown => Some(vec![Line::from(vec![
            Span::styled(
                format!("{:<16}", "Origin"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled("unknown", Style::default().fg(Color::DarkGray)),
        ])]),
        Origin::Unsupported => None,
    }
}
