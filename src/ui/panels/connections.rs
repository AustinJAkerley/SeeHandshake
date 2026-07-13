// SPDX-License-Identifier: MIT

//! Left panel: list of tracked connections.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::ui::app::{App, PaneFocus};

/// Render the connection list panel.
pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .connections()
        .map(|c| {
            let label = c
                .handshake
                .sni
                .clone()
                .unwrap_or_else(|| c.key.server_ip.to_string());
            ListItem::new(Line::from(vec![Span::raw(label)]))
        })
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.selected_index().min(items.len() - 1)));
    }

    let focused = app.focus() == PaneFocus::Connections;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let title = if focused {
        format!("Connections ({}) [focus]", items.len())
    } else {
        format!("Connections ({})", items.len())
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("\u{25B6} ");

    f.render_stateful_widget(list, area, &mut state);
}
