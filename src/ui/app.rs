// SPDX-License-Identifier: MIT

//! UI-thread state machine.
//!
//! [`App`] owns the ordered list of tracked connections, the current
//! selection, and the state that drives the always-three-pane layout:
//! which pane has keyboard focus, which record is selected inside the
//! middle pane, which section is selected inside the right pane, whether
//! the right pane is showing connection metadata or per-record sections,
//! and per-section expansion state.
//!
//! The state transitions here are intentionally simple; the event loop in
//! [`crate::ui::run_live`] is a thin adapter that maps key presses onto
//! these methods.

use std::collections::HashMap;

use crate::model::record::RecordEvent;
use crate::model::{ConnectionKey, ConnectionState, HandshakeStage};
use crate::ui::event::UiEvent;
use crate::ui::sections::{sections_for, Section};

/// Which pane currently has keyboard focus.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PaneFocus {
    /// Left pane: list of tracked connections.
    #[default]
    Connections,
    /// Middle pane: list of TLS records for the selected connection.
    Records,
    /// Right pane: either connection metadata or the sectioned per-record
    /// view, depending on [`RightPaneMode`].
    Right,
}

/// What the right pane is currently showing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RightPaneMode {
    /// Connection-level summary: SNI, cipher, key group, ALPN, origin.
    /// This is the default when a connection is first selected.
    #[default]
    Metadata,
    /// Sectioned per-record view. Activated when the user starts arrowing
    /// through records or explicitly focuses the right pane.
    Sections,
}

/// What the middle pane is rendering. Bound to `[f]`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MiddlePaneMode {
    /// Chronological list of TLS records with size-aware labels (default).
    #[default]
    Records,
    /// Schematic Client\u{2194}Server flow diagram that lights up the current
    /// [`crate::model::HandshakeStage`].
    Flow,
}

/// Application state owned by the UI thread.
///
/// The middle (records) pane is modelled as a virtual list whose row 0 is a
/// `Metadata` pseudo-entry and rows `1..=records.len()` are the actual
/// records. [`Self::right_mode`] is derived from [`Self::records_row`]: row 0
/// shows connection metadata, everything else shows the per-record sections
/// view.
#[derive(Debug, Default)]
pub struct App {
    order: Vec<ConnectionKey>,
    connections: HashMap<ConnectionKey, ConnectionState>,
    selected: usize,
    focus: PaneFocus,
    middle_mode: MiddlePaneMode,
    records_row: usize,
    section_index: usize,
    education: bool,
    /// Whether the full-screen reference-diagram overlay (bound to `[d]`)
    /// is active. Independent of the middle-pane mode.
    diagram_overlay: bool,
    tick_count: u64,
    evicted: usize,
}

impl App {
    /// Create an empty [`App`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Toggle the educational overlay (globally expand section long-form
    /// text).
    pub fn toggle_education(&mut self) {
        self.education = !self.education;
    }

    /// Whether the educational overlay is active.
    #[must_use]
    pub fn education(&self) -> bool {
        self.education
    }

    /// Which pane currently has keyboard focus.
    #[must_use]
    pub fn focus(&self) -> PaneFocus {
        self.focus
    }

    /// What the middle pane is currently rendering.
    #[must_use]
    pub fn middle_mode(&self) -> MiddlePaneMode {
        self.middle_mode
    }

    /// Flip the middle pane between the record list and the schematic
    /// Client\u{2194}Server flow diagram. Bound to `[f]`.
    ///
    /// When switching into the Flow view, park the cursor on the
    /// ClientHello so the diagram starts at the first step rather than the
    /// connection's current stage (which is `ApplicationData` — the end —
    /// once the handshake completes).
    pub fn toggle_middle_mode(&mut self) {
        self.middle_mode = match self.middle_mode {
            MiddlePaneMode::Records => MiddlePaneMode::Flow,
            MiddlePaneMode::Flow => MiddlePaneMode::Records,
        };
        if self.middle_mode == MiddlePaneMode::Flow {
            if let Some(row) = self.client_hello_row() {
                self.records_row = row;
                self.on_records_row_changed();
            }
        }
    }

    /// Virtual-list row (1-based, matching [`Self::records_row`]) of the
    /// first ClientHello record in the selected connection, if any.
    fn client_hello_row(&self) -> Option<usize> {
        use crate::model::record::{DecodedHandshake, RecordBody};
        let conn = self.selected()?;
        conn.records
            .iter()
            .position(|r| {
                matches!(
                    &r.body,
                    RecordBody::Handshake(DecodedHandshake::ClientHello(_))
                )
            })
            .map(|idx| idx + 1)
    }

    /// Toggle the full-screen reference-diagram overlay (`[d]`).
    pub fn toggle_diagram(&mut self) {
        self.diagram_overlay = !self.diagram_overlay;
    }

    /// Whether the reference-diagram overlay is active.
    #[must_use]
    pub fn diagram(&self) -> bool {
        self.diagram_overlay
    }

    /// Drop every tracked connection and reset selection/focus. Bound to
    /// `[w]`. The `evicted` counter is preserved so the status line stays
    /// truthful about the session's history.
    pub fn clear_connections(&mut self) {
        self.order.clear();
        self.connections.clear();
        self.selected = 0;
        self.focus = PaneFocus::Connections;
        self.records_row = 0;
        self.section_index = 0;
    }

    /// What the right pane is currently showing. Derived from the middle
    /// pane's cursor: row 0 (the Metadata pseudo-row) shows `Metadata`,
    /// any actual record shows `Sections`.
    #[must_use]
    pub fn right_mode(&self) -> RightPaneMode {
        if self.records_row == 0 {
            RightPaneMode::Metadata
        } else {
            RightPaneMode::Sections
        }
    }

    /// Move focus one pane to the left (clamped at Connections).
    pub fn focus_left(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Connections => PaneFocus::Connections,
            PaneFocus::Records => PaneFocus::Connections,
            PaneFocus::Right => PaneFocus::Records,
        };
    }

    /// Move focus one pane to the right (clamped at Right). Landing on
    /// Right implicitly advances past the Metadata pseudo-row if the user
    /// hasn't picked a real record yet — the right pane has nothing to
    /// interact with in `Metadata` mode.
    pub fn focus_right(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Connections => PaneFocus::Records,
            PaneFocus::Records => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Right,
        };
        if self.focus == PaneFocus::Right {
            self.advance_past_metadata_row();
        }
    }

    /// Cycle focus L\u{2192}C\u{2192}R\u{2192}L. Bound to Tab.
    pub fn focus_cycle(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Connections => PaneFocus::Records,
            PaneFocus::Records => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Connections,
        };
        if self.focus == PaneFocus::Right {
            self.advance_past_metadata_row();
        }
    }

    /// Up-arrow: dispatch by focus.
    pub fn select_prev(&mut self) {
        match self.focus {
            PaneFocus::Connections => self.connection_prev(),
            PaneFocus::Records => self.record_prev(),
            PaneFocus::Right => self.section_prev(),
        }
    }

    /// Down-arrow: dispatch by focus.
    pub fn select_next(&mut self) {
        match self.focus {
            PaneFocus::Connections => self.connection_next(),
            PaneFocus::Records => self.record_next(),
            PaneFocus::Right => self.section_next(),
        }
    }

    fn connection_prev(&mut self) {
        if self.order.is_empty() {
            return;
        }
        let before = self.selected;
        self.selected = self.selected.saturating_sub(1);
        if self.selected != before {
            self.on_connection_changed();
        }
    }

    fn connection_next(&mut self) {
        if self.order.is_empty() {
            return;
        }
        let last = self.order.len() - 1;
        let before = self.selected;
        if self.selected < last {
            self.selected += 1;
        }
        if self.selected != before {
            self.on_connection_changed();
        }
    }

    fn on_connection_changed(&mut self) {
        self.records_row = 0;
        self.section_index = 0;
    }

    fn record_prev(&mut self) {
        let before = self.records_row;
        self.records_row = self.records_row.saturating_sub(1);
        if self.records_row != before {
            self.on_records_row_changed();
        }
    }

    fn record_next(&mut self) {
        // records_row ranges over 0..=records.len(); row 0 is the Metadata
        // pseudo-entry, so the cap is records.len() (inclusive of the last
        // real record at row records.len()).
        let cap = self.selected_record_count();
        let before = self.records_row;
        if self.records_row < cap {
            self.records_row += 1;
        }
        if self.records_row != before {
            self.on_records_row_changed();
        }
    }

    fn on_records_row_changed(&mut self) {
        self.section_index = 0;
    }

    fn selected_is_tls12(&self) -> bool {
        use crate::model::tls::TlsVersion;
        self.selected()
            .and_then(|c| c.handshake.tls_version)
            .is_some_and(|v| {
                matches!(
                    v,
                    TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12
                )
            })
    }

    /// Whether the currently selected connection negotiated a pre-TLS-1.3
    /// version (used by the Flow diagram to pick the right stage list).
    #[must_use]
    pub fn is_tls12(&self) -> bool {
        self.selected_is_tls12()
    }

    /// Stage inferred from the currently selected record, if any. Returns
    /// `None` when the Metadata pseudo-row is selected or the record can't
    /// be mapped to a canonical stage (e.g. bare ChangeCipherSpec).
    #[must_use]
    pub fn selected_record_stage(&self) -> Option<HandshakeStage> {
        use crate::model::record::{DecodedHandshake, RecordBody, RecordDirection};
        let conn = self.selected()?;
        if self.records_row == 0 {
            return None;
        }
        let record = conn.records.get(self.records_row - 1)?;
        match &record.body {
            RecordBody::Handshake(hs) => match hs {
                DecodedHandshake::ClientHello(_) => Some(HandshakeStage::ClientHello),
                DecodedHandshake::ServerHello(_) | DecodedHandshake::HelloRetryRequest(_) => {
                    Some(HandshakeStage::ServerHello)
                }
                DecodedHandshake::Unknown { msg_type, .. } => match *msg_type {
                    11 => Some(if self.selected_is_tls12() {
                        HandshakeStage::ServerCertificate
                    } else {
                        HandshakeStage::Certificate
                    }),
                    12 => Some(HandshakeStage::ServerKeyExchange),
                    14 => Some(HandshakeStage::ServerHelloDone),
                    16 => Some(HandshakeStage::ClientKeyExchange),
                    20 => Some(match record.direction {
                        RecordDirection::ClientToServer => HandshakeStage::ClientFinished,
                        RecordDirection::ServerToClient => HandshakeStage::ServerFinished,
                    }),
                    _ => None,
                },
            },
            RecordBody::EncryptedHandshake { inferred_label, .. } => {
                let l = *inferred_label;
                if l.contains("Finished only") {
                    Some(match record.direction {
                        RecordDirection::ClientToServer => HandshakeStage::ClientFinished,
                        RecordDirection::ServerToClient => HandshakeStage::ServerFinished,
                    })
                } else if l.contains("application data")
                    || l.contains("early data")
                    || l.contains("NewSessionTicket")
                {
                    Some(HandshakeStage::ApplicationData)
                } else if l.contains("Finished") {
                    // Combined flight ending in Finished (e.g. EE+Cert+CV+Finished).
                    Some(match record.direction {
                        RecordDirection::ClientToServer => HandshakeStage::ClientFinished,
                        RecordDirection::ServerToClient => HandshakeStage::ServerFinished,
                    })
                } else {
                    // EncryptedExtensions / Certificate / CertificateVerify —
                    // TLS 1.3 encrypted server flight sits at Certificate.
                    Some(HandshakeStage::Certificate)
                }
            }
            RecordBody::ChangeCipherSpec => None,
        }
    }

    fn section_prev(&mut self) {
        if self.records_row == 0 {
            return;
        }
        self.section_index = self.section_index.saturating_sub(1);
    }

    fn section_next(&mut self) {
        if self.records_row == 0 {
            return;
        }
        let cap = self.section_count().saturating_sub(1);
        if self.section_index < cap {
            self.section_index += 1;
        }
    }

    fn advance_past_metadata_row(&mut self) {
        if self.records_row == 0 && self.selected_record_count() > 0 {
            self.records_row = 1;
            self.on_records_row_changed();
        }
    }

    /// Whether the section at index `i` should render its long-form text.
    /// Now globally gated by the `[e]` toggle — there is no per-section
    /// expansion.
    #[must_use]
    pub fn is_section_expanded(&self, _i: usize) -> bool {
        self.education
    }

    /// The record currently selected in the middle pane, if any. Returns
    /// `None` when the cursor is on the Metadata pseudo-row.
    #[must_use]
    pub fn record_selected(&self) -> Option<&RecordEvent> {
        if self.records_row == 0 {
            return None;
        }
        self.selected()
            .and_then(|c| c.records.get(self.records_row - 1))
    }

    /// Cursor position within the middle pane's virtual list. Row 0 is the
    /// Metadata pseudo-entry; rows `1..=records.len()` map to
    /// `records[row - 1]`. This is what the records list widget should
    /// highlight.
    #[must_use]
    pub fn records_row(&self) -> usize {
        self.records_row
    }

    /// Sections for the currently selected record, if any.
    #[must_use]
    pub fn sections(&self) -> Vec<Section> {
        self.record_selected().map(sections_for).unwrap_or_default()
    }

    /// Index of the currently selected section in the right pane.
    #[must_use]
    pub fn section_index(&self) -> usize {
        self.section_index
    }

    fn selected_record_count(&self) -> usize {
        self.selected().map(|c| c.records.len()).unwrap_or(0)
    }

    fn section_count(&self) -> usize {
        self.sections().len()
    }

    /// Advance the animation tick counter.
    pub fn tick(&mut self) {
        self.tick_count = self.tick_count.wrapping_add(1);
    }

    /// Read the current tick counter.
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
                let is_selected = self.order.get(self.selected).is_some_and(|k| *k == key);
                self.connections.insert(key, *state);
                // If the currently selected connection just gained records,
                // keep the selected record and section indices in range.
                if is_selected {
                    self.clamp_indices();
                }
            }
            UiEvent::StaleEvicted(n) => {
                self.evicted = self.evicted.saturating_add(n);
                let selected_key = self.order.get(self.selected).copied();
                self.order.retain(|k| self.connections.contains_key(k));
                if self.order.is_empty() {
                    self.selected = 0;
                    self.on_connection_changed();
                    return;
                }
                match selected_key.and_then(|k| self.order.iter().position(|x| *x == k)) {
                    Some(pos) => self.selected = pos,
                    None => {
                        self.selected = self.selected.min(self.order.len() - 1);
                        self.on_connection_changed();
                    }
                }
                self.clamp_indices();
            }
        }
    }

    fn clamp_indices(&mut self) {
        // records_row indexes into 0..=records.len(); saturate against
        // records.len() (inclusive) when the list shrinks under us.
        let row_cap = self.selected_record_count();
        if self.records_row > row_cap {
            self.records_row = row_cap;
        }
        let sec_cap = self.section_count().saturating_sub(1);
        if self.section_index > sec_cap {
            self.section_index = sec_cap;
        }
    }

    /// Iterate over connections in display order.
    pub fn connections(&self) -> impl Iterator<Item = &ConnectionState> {
        self.order
            .iter()
            .filter_map(move |k| self.connections.get(k))
    }

    /// Index of the currently selected connection row.
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

    /// Origin (owning process) of the currently selected connection, if
    /// attribution has been resolved.
    #[must_use]
    pub fn selected_origin(&self) -> Option<&crate::origin::Origin> {
        self.selected().and_then(|s| s.handshake.origin.as_ref())
    }

    /// Cumulative number of stale-evicted connections.
    #[must_use]
    pub fn evicted(&self) -> usize {
        self.evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::connection::Direction;
    use crate::model::ConnectionKey;
    use crate::origin::{FixedResolver, Origin};
    use crate::tracker::ConnectionTracker;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const CLIENT_HELLO_RECORD: &[u8] = include_bytes!("../../tests/data/client_hello_tls13.bin");
    const SERVER_HELLO_RECORD: &[u8] = include_bytes!("../../tests/data/server_hello_tls13.bin");

    fn seeded_app_one_connection() -> App {
        let key = ConnectionKey::canonical(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            54321,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        );
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let mut tracker =
            ConnectionTracker::with_resolver(Box::new(FixedResolver(Origin::Unknown)));
        tracker
            .ingest(key, Direction::ClientToServer, a, b, CLIENT_HELLO_RECORD, 0)
            .unwrap();
        let state = tracker
            .ingest(key, Direction::ServerToClient, b, a, SERVER_HELLO_RECORD, 5)
            .unwrap()
            .unwrap();
        let mut app = App::new();
        app.handle_ui_event(UiEvent::HandshakeUpdated(Box::new(state)));
        app
    }

    fn seeded_app_two_connections() -> App {
        let mut app = seeded_app_one_connection();
        let key2 = ConnectionKey::canonical(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            54322,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54322);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let mut tracker =
            ConnectionTracker::with_resolver(Box::new(FixedResolver(Origin::Unknown)));
        let state = tracker
            .ingest(
                key2,
                Direction::ClientToServer,
                a,
                b,
                CLIENT_HELLO_RECORD,
                10,
            )
            .unwrap()
            .unwrap();
        app.handle_ui_event(UiEvent::HandshakeUpdated(Box::new(state)));
        app
    }

    #[test]
    fn right_pane_defaults_to_metadata() {
        let app = seeded_app_one_connection();
        assert_eq!(app.right_mode(), RightPaneMode::Metadata);
        assert_eq!(app.focus(), PaneFocus::Connections);
    }

    #[test]
    fn focus_right_from_records_switches_to_sections() {
        let mut app = seeded_app_one_connection();
        app.focus_right(); // -> Records
        assert_eq!(app.focus(), PaneFocus::Records);
        assert_eq!(app.right_mode(), RightPaneMode::Metadata);
        app.focus_right(); // -> Right, flips to Sections
        assert_eq!(app.focus(), PaneFocus::Right);
        assert_eq!(app.right_mode(), RightPaneMode::Sections);
    }

    #[test]
    fn arrowing_records_switches_right_to_sections() {
        let mut app = seeded_app_one_connection();
        app.focus_right(); // Connections -> Records
        assert_eq!(app.right_mode(), RightPaneMode::Metadata);
        app.select_next(); // arrow within Records
        assert_eq!(app.right_mode(), RightPaneMode::Sections);
    }

    #[test]
    fn focus_left_clamps_at_connections() {
        let mut app = seeded_app_one_connection();
        app.focus_left();
        assert_eq!(app.focus(), PaneFocus::Connections);
        app.focus_right();
        app.focus_right();
        assert_eq!(app.focus(), PaneFocus::Right);
        app.focus_right();
        assert_eq!(app.focus(), PaneFocus::Right, "clamped at Right");
    }

    #[test]
    fn changing_connection_resets_right_to_metadata() {
        let mut app = seeded_app_two_connections();
        // Engage records on connection 0 to flip to Sections.
        app.focus_right();
        app.select_next();
        assert_eq!(app.right_mode(), RightPaneMode::Sections);
        // Move focus back to Connections and pick a different one.
        app.focus_left();
        app.focus_left();
        assert_eq!(app.focus(), PaneFocus::Connections);
        app.select_next();
        assert_eq!(app.right_mode(), RightPaneMode::Metadata);
        assert_eq!(app.records_row(), 0);
        assert_eq!(app.section_index(), 0);
    }

    #[test]
    fn arrowing_up_from_first_record_returns_to_metadata() {
        // The Metadata pseudo-row is the reason we can revisit the
        // connection summary without switching connections.
        let mut app = seeded_app_one_connection();
        app.focus_right(); // Connections -> Records
        app.select_next(); // records_row 0 -> 1, Sections
        assert_eq!(app.right_mode(), RightPaneMode::Sections);
        app.select_prev(); // records_row 1 -> 0, back to Metadata
        assert_eq!(app.records_row(), 0);
        assert_eq!(app.right_mode(), RightPaneMode::Metadata);
    }

    #[test]
    fn enter_at_right_no_longer_toggles_per_section() {
        // Per-section expansion was removed; only the global [e] toggle
        // controls whether edu prose is rendered.
        let mut app = seeded_app_one_connection();
        app.focus_right();
        app.focus_right();
        assert_eq!(app.right_mode(), RightPaneMode::Sections);
        assert!(!app.is_section_expanded(0));
        app.toggle_education();
        assert!(app.is_section_expanded(0));
    }

    #[test]
    fn education_toggle_expands_all_sections() {
        let mut app = seeded_app_one_connection();
        app.focus_right();
        app.focus_right();
        assert!(!app.is_section_expanded(3));
        app.toggle_education();
        assert!(app.is_section_expanded(3));
        assert!(app.is_section_expanded(0));
    }

    #[test]
    fn up_down_dispatch_by_focus() {
        let mut app = seeded_app_two_connections();
        // Connections focus: moves selected connection.
        assert_eq!(app.selected_index(), 0);
        app.select_next();
        assert_eq!(app.selected_index(), 1);
        // Records focus: moves record_index and flips to Sections.
        app.focus_right();
        app.select_next();
        assert_eq!(app.right_mode(), RightPaneMode::Sections);
        // Right focus (Sections): moves section_index.
        app.focus_right();
        let before = app.section_index();
        app.select_next();
        assert!(app.section_index() >= before);
    }
}
