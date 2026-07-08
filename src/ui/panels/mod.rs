// SPDX-License-Identifier: MIT

//! Three-panel Ratatui rendering.

pub mod connections;
pub mod flow;
pub mod metadata;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::ui::app::App;

/// Render one frame of the UI.
pub fn render(f: &mut Frame<'_>, app: &App) {
    let area = f.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(40),
        ])
        .split(outer[0]);

    connections::render(f, app, panels[0]);
    flow::render(f, app, panels[1]);
    metadata::render(f, app, panels[2]);

    // Status line.
    let status = Line::from(vec![
        Span::styled("seehandshake", Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::raw(format!("connections: {}", app.connections().count())),
        Span::raw("  "),
        Span::raw(format!("evicted: {}", app.evicted())),
        Span::raw("   "),
        Span::styled("[q]", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("[e]", Style::default().fg(Color::Yellow)),
        Span::raw(if app.education() {
            " education: ON"
        } else {
            " education: off"
        }),
        Span::raw("  "),
        Span::styled("[\u{2191}/\u{2193}]", Style::default().fg(Color::Yellow)),
        Span::raw(" select"),
    ]);
    f.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::NONE)),
        outer[1],
    );
}
