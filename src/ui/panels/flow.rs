// SPDX-License-Identifier: MIT

//! Center panel: animated handshake flow.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::HandshakeStage;
use crate::ui::app::App;
use crate::ui::education::explain;

/// Render the center handshake-flow panel.
pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let current_stage = app
        .selected()
        .map_or(HandshakeStage::Idle, |c| c.handshake.stage);

    let mut lines: Vec<Line> = Vec::new();
    for (i, stage) in HandshakeStage::ordered().iter().enumerate() {
        let is_active = *stage == current_stage;
        let is_past = stage_index(current_stage).is_some_and(|c| i < c);
        let style = if is_active {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else if is_past {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
        };

        let marker = if is_active {
            animated_marker(app.tick_count())
        } else if is_past {
            "\u{2713} "
        } else {
            "  "
        };

        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(stage.label(), style),
        ]));

        if i + 1 < HandshakeStage::ordered().len() {
            lines.push(Line::from(Span::styled(
                "  \u{2193}",
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

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

fn stage_index(stage: HandshakeStage) -> Option<usize> {
    HandshakeStage::ordered().iter().position(|s| *s == stage)
}

fn animated_marker(tick: u64) -> &'static str {
    // Cycle through a small set of glyphs at each tick.
    match tick % 4 {
        0 | 2 => "\u{25CF} ",
        1 => "\u{25CB} ",
        _ => "\u{25D0} ",
    }
}
