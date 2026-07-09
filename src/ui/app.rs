// SPDX-License-Identifier: MIT

//! UI-thread state machine.
//!
//! [`App`] holds an ordered list of tracked connections (so that keyboard
//! navigation and rendering are deterministic), the current selection, the
//! educational-mode toggle, and a tick counter used to animate the center
//! panel's arrows.

use std::collections::HashMap;

use crate::model::{ConnectionKey, ConnectionState};
use crate::ui::event::UiEvent;

/// Application state owned by the UI thread.
#[derive(Debug, Default)]
pub struct App {
    /// Insertion-ordered connection keys (for stable rendering and
    /// navigation).
    order: Vec<ConnectionKey>,
    /// Latest state for each connection, keyed by [`ConnectionKey`].
    connections: HashMap<ConnectionKey, ConnectionState>,
    /// Index into [`Self::order`] of the currently selected connection.
    selected: usize,
    /// Whether the educational overlay is active.
    education: bool,
    /// Whether the reference diagram overlay is active.
    diagram_overlay: bool,
    /// Monotonic tick counter used for arrow animation.
    tick_count: u64,
    /// Cumulative number of stale-evicted connections (for the status
    /// line).
    evicted: usize,
}

impl App {
    /// Create an empty [`App`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Toggle the educational overlay.
    pub fn toggle_education(&mut self) {
        self.education = !self.education;
    }

    /// Whether the educational overlay is active.
    #[must_use]
    pub fn education(&self) -> bool {
        self.education
    }

    /// Toggle the reference diagram overlay.
    pub fn toggle_diagram(&mut self) {
        self.diagram_overlay = !self.diagram_overlay;
    }

    /// Whether the reference diagram overlay is active.
    #[must_use]
    pub fn diagram(&self) -> bool {
        self.diagram_overlay
    }

    /// Move the selection cursor up one position (saturating at 0).
    pub fn select_prev(&mut self) {
        if !self.order.is_empty() {
            self.selected = self.selected.saturating_sub(1);
        }
    }

    /// Move the selection cursor down one position (saturating at
    /// `len - 1`).
    pub fn select_next(&mut self) {
        if !self.order.is_empty() {
            let last = self.order.len() - 1;
            if self.selected < last {
                self.selected += 1;
            }
        }
    }

    /// Advance the animation tick counter.
    pub fn tick(&mut self) {
        self.tick_count = self.tick_count.wrapping_add(1);
    }

    /// Read the current tick counter (used by panel renderers).
    #[must_use]
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Consume a [`UiEvent`] from the parser/tracker thread.
    pub fn handle_ui_event(&mut self, evt: UiEvent) {
        match evt {
            UiEvent::HandshakeUpdated(state) => {
                let key = state.key;
                if !self.connections.contains_key(&key) {
                    self.order.push(key);
                }
                self.connections.insert(key, *state);
            }
            UiEvent::StaleEvicted(n) => {
                self.evicted = self.evicted.saturating_add(n);
                self.order.retain(|k| self.connections.contains_key(k));
                if self.selected >= self.order.len().max(1) {
                    self.selected = self.order.len().saturating_sub(1);
                }
            }
        }
    }

    /// Iterate over connections in display order.
    pub fn connections(&self) -> impl Iterator<Item = &ConnectionState> {
        self.order
            .iter()
            .filter_map(move |k| self.connections.get(k))
    }

    /// Index of the currently selected row.
    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// The currently selected connection state, if any.
    #[must_use]
    pub fn selected(&self) -> Option<&ConnectionState> {
        self.order
            .get(self.selected)
            .and_then(|k| self.connections.get(k))
    }

    /// Cumulative number of stale-evicted connections.
    #[must_use]
    pub fn evicted(&self) -> usize {
        self.evicted
    }
}
