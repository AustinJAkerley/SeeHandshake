// SPDX-License-Identifier: MIT

//! Right panel: connection metadata (default) or per-record sections.
//!
//! The right pane starts in [`RightPaneMode::Metadata`] and flips to
//! [`RightPaneMode::Sections`] once the user engages with the record
//! timeline (arrows within Records, or focus moved to the right pane).
//! Switching to a different connection resets the mode back to
//! `Metadata`.
//!
//! In Sections mode the pane behaves like a scrolling list: the paragraph
//! is offset so the currently selected section stays visible even when the
//! total content is taller than the pane. Scroll is recomputed each frame
//! from the section-index-to-line-row map, so no scroll state lives on
//! `App`.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::ui::app::{App, PaneFocus, RightPaneMode};
use crate::ui::panels::metadata::metadata_lines;
use crate::ui::sections::Section;

/// Render the right pane.
pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let focused = app.focus() == PaneFocus::Right;

    // Reserve two rows/cols for the surrounding block borders when
    // computing wrap width and viewport height.
    let inner_w = area.width.saturating_sub(2);
    let inner_h = area.height.saturating_sub(2);

    let (title, lines, scroll) = match app.right_mode() {
        RightPaneMode::Metadata => (
            "Metadata".to_string(),
            wrap_lines_with_indent(metadata_lines(app), inner_w),
            0u16,
        ),
        RightPaneMode::Sections => {
            let (title, lines, bounds) = sections_view(app, inner_w);
            let scroll = scroll_offset(&bounds, app.section_index(), inner_h);
            (title, lines, scroll)
        }
    };

    let title = if focused {
        format!("{title} [focus]")
    } else {
        title
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
        .scroll((scroll, 0));
    f.render_widget(paragraph, area);
}

/// Per-section start line and line count in the pre-wrap `lines` vector.
#[derive(Clone, Copy, Debug)]
struct SectionSpan {
    start: usize,
    len: usize,
}

fn sections_view(app: &App, inner_w: u16) -> (String, Vec<Line<'static>>, Vec<SectionSpan>) {
    let sections = app.sections();
    if sections.is_empty() {
        return (
            "Sections".to_string(),
            vec![Line::from(Span::styled(
                "No record selected. Arrow through the Records pane to explore.",
                Style::default().fg(Color::DarkGray),
            ))],
            Vec::new(),
        );
    }

    let record_label = app
        .record_selected()
        .map(record_label)
        .unwrap_or_else(|| "record".to_string());
    let title = format!("Sections \u{2014} {record_label}");

    let selected = app.section_index();
    let show_education = app.education();
    let mut lines = Vec::new();
    let mut bounds = Vec::with_capacity(sections.len());
    for (i, s) in sections.iter().enumerate() {
        if i > 0 {
            lines.push(separator_line(inner_w));
        }
        let start = lines.len();
        let is_selected = selected == i;
        let mut section_lines = Vec::new();
        render_section(&mut section_lines, i, s, is_selected, show_education);
        for line in section_lines {
            wrap_line(line, inner_w, &mut lines);
        }
        let len = lines.len() - start;
        bounds.push(SectionSpan { start, len });
        lines.push(Line::from(""));
    }
    (title, lines, bounds)
}

fn separator_line(inner_w: u16) -> Line<'static> {
    let width = inner_w.max(1) as usize;
    let rule: String = "\u{2500}".repeat(width);
    Line::from(Span::styled(
        rule,
        Style::default().fg(Color::Rgb(255, 140, 0)),
    ))
}

/// Compute a scroll offset (in rows) that keeps the selected section
/// visible without over-scrolling past the last row. Bounds already index
/// post-wrap lines, so no wrap-row estimation is needed.
fn scroll_offset(bounds: &[SectionSpan], selected: usize, inner_h: u16) -> u16 {
    if bounds.is_empty() || inner_h == 0 {
        return 0;
    }
    let Some(span) = bounds.get(selected) else {
        return 0;
    };

    let sel_start_row = span.start as u32;
    let sel_height = span.len as u32;
    let total_rows: u32 = bounds
        .last()
        .map(|b| (b.start + b.len) as u32)
        .unwrap_or(0);
    let max_scroll = total_rows.saturating_sub(u32::from(inner_h));

    // Peek rows: keep a few rows of the next section visible below the
    // selected one so the user can tell content continues (the orange
    // separator + a hint of the following header).
    let peek: u32 = 3;

    let desired = if sel_height + peek <= u32::from(inner_h) {
        let bottom = sel_start_row + sel_height + peek;
        bottom.saturating_sub(u32::from(inner_h))
    } else if sel_height <= u32::from(inner_h) {
        let bottom = sel_start_row + sel_height;
        bottom.saturating_sub(u32::from(inner_h))
    } else {
        sel_start_row
    };
    let desired = desired.max(sel_start_row.saturating_sub(u32::from(inner_h).saturating_sub(1)));
    let clamped = desired.min(max_scroll).min(sel_start_row);
    u16::try_from(clamped).unwrap_or(u16::MAX)
}

/// Wrap a batch of lines with hanging indent preserved on continuations.
fn wrap_lines_with_indent(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        wrap_line(line, width, &mut out);
    }
    out
}

/// Wrap a single `Line` into `out`, preserving span styles and prepending
/// the line's leading whitespace as a hanging indent on continuation rows.
fn wrap_line(line: Line<'static>, width: u16, out: &mut Vec<Line<'static>>) {
    let width_u = width as usize;
    if width_u == 0 || line.width() <= width_u {
        out.push(line);
        return;
    }

    // Leading indent = leading spaces of concatenated content.
    let mut indent: usize = 0;
    'outer: for span in &line.spans {
        for c in span.content.chars() {
            if c == ' ' {
                indent += 1;
            } else {
                break 'outer;
            }
        }
    }
    // Guarantee forward progress on very narrow panes.
    let indent = indent.min(width_u.saturating_sub(1));

    // Flatten to a (char, style) buffer for straightforward slicing.
    let total_chars: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
    let mut chars: Vec<(char, Style)> = Vec::with_capacity(total_chars);
    for span in &line.spans {
        let st = span.style;
        for c in span.content.chars() {
            chars.push((c, st));
        }
    }

    let n = chars.len();
    let mut i = 0;
    let mut is_first = true;
    while i < n {
        let avail = if is_first {
            width_u
        } else {
            width_u.saturating_sub(indent)
        };
        if avail == 0 {
            break;
        }

        let hard_end = (i + avail).min(n);
        let mut end = hard_end;
        // Word-wrap: prefer to break at the last space in range.
        if end < n {
            let mut k = end;
            let min_content = if is_first { i + indent + 1 } else { i + 1 };
            while k > min_content && chars[k - 1].0 != ' ' {
                k -= 1;
            }
            if k > min_content {
                end = k;
            }
        }

        let mut spans: Vec<Span<'static>> = Vec::new();
        if !is_first && indent > 0 {
            spans.push(Span::raw(" ".repeat(indent)));
        }
        // Coalesce consecutive chars sharing a style.
        let mut chunk_start = i;
        let mut cur_style = chars[i].1;
        for j in (i + 1)..end {
            if chars[j].1 != cur_style {
                let s: String = chars[chunk_start..j].iter().map(|(c, _)| *c).collect();
                spans.push(Span::styled(s, cur_style));
                chunk_start = j;
                cur_style = chars[j].1;
            }
        }
        let s: String = chars[chunk_start..end].iter().map(|(c, _)| *c).collect();
        spans.push(Span::styled(s, cur_style));
        out.push(Line::from(spans));

        i = end;
        is_first = false;
    }
}

fn record_label(r: &crate::model::record::RecordEvent) -> String {
    use crate::model::record::{DecodedHandshake, RecordBody};
    match &r.body {
        RecordBody::Handshake(hs) => match hs {
            DecodedHandshake::ClientHello(_) => "ClientHello".into(),
            DecodedHandshake::ServerHello(_) => "ServerHello".into(),
            DecodedHandshake::HelloRetryRequest(_) => "HelloRetryRequest".into(),
            DecodedHandshake::Unknown { msg_type, .. } => {
                crate::model::record::handshake_type_name(*msg_type).to_string()
            }
        },
        RecordBody::EncryptedHandshake { inferred_label, .. } => (*inferred_label).to_string(),
        RecordBody::ChangeCipherSpec => "ChangeCipherSpec".to_string(),
    }
}

fn render_section(
    out: &mut Vec<Line<'static>>,
    _index: usize,
    s: &Section,
    is_selected: bool,
    show_education: bool,
) {
    let cursor = if is_selected { "\u{25B6} " } else { "  " };
    let title_style = if is_selected {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD | Modifier::REVERSED)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };

    out.push(Line::from(vec![
        Span::styled(cursor.to_string(), Style::default().fg(Color::Cyan)),
        Span::styled(s.title.clone(), title_style),
        Span::raw("  "),
        Span::styled(
            format!("\u{00B7} {}", s.direction_hint),
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    for vl in &s.value_lines {
        let mut spans: Vec<Span<'static>> = vec![Span::raw("    ")];
        for span in vl.spans.iter() {
            spans.push(span.clone());
        }
        out.push(Line::from(spans));
    }

    // Educational prose (edu_short + labeled details) only renders when the
    // global `e` toggle is on. Default view = wire bytes only.
    if show_education {
        out.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(
                s.edu_short.to_string(),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            ),
        ]));

        for detail in s.edu_details {
            out.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    format!("{}: ", detail.label),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(detail.body.to_string(), Style::default().fg(Color::White)),
            ]));
        }
    }
}
