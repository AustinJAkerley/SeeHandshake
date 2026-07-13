// SPDX-License-Identifier: MIT

//! Three-panel Ratatui rendering.

pub mod connections;
pub mod diagram;
pub mod flow;
pub mod metadata;
pub mod records;
pub mod right;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::ui::app::{App, MiddlePaneMode};

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
    match app.middle_mode() {
        MiddlePaneMode::Records => records::render(f, app, panels[1]),
        MiddlePaneMode::Flow => flow::render(f, app, panels[1]),
    }
    right::render(f, app, panels[2]);

    // Reference diagram overlay (toggled by [d]).
    if app.diagram() {
        diagram::render(f, outer[0]);
    }

    // Status line.
    let spans = vec![
        Span::styled("seehandshake", Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::raw(format!("connections: {}", app.connections().count())),
        Span::raw("  "),
        Span::raw(format!("evicted: {}", app.evicted())),
        Span::raw("   "),
        Span::styled("[q]", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("[w]", Style::default().fg(Color::Yellow)),
        Span::raw(" wipe  "),
        Span::styled("[\u{2190}/\u{2192}]", Style::default().fg(Color::Yellow)),
        Span::raw(" pane  "),
        Span::styled("[\u{2191}/\u{2193}]", Style::default().fg(Color::Yellow)),
        Span::raw(" select  "),
        Span::styled("[enter]", Style::default().fg(Color::Yellow)),
        Span::raw(" expand  "),
        Span::styled("[esc]", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("[e]", Style::default().fg(Color::Yellow)),
        Span::raw(if app.education() {
            " education: ON  "
        } else {
            " education: off  "
        }),
        Span::styled("[f]", Style::default().fg(Color::Yellow)),
        Span::raw(match app.middle_mode() {
            MiddlePaneMode::Records => " flow: records  ",
            MiddlePaneMode::Flow => " flow: diagram  ",
        }),
        Span::styled("[d]", Style::default().fg(Color::Yellow)),
        Span::raw(if app.diagram() {
            " reference: ON"
        } else {
            " reference"
        }),
    ];
    let status = Line::from(spans);
    f.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::NONE)),
        outer[1],
    );
}
