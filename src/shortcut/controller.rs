use crate::broker::RelayPacket;
use crate::shortcut::{
    control::ShortcutTicket,
    device::{DeviceEvent, DeviceHandle},
    state::{RouteManager, SessionKey, ShortcutManager},
};
use anyhow::Result;
use tokio::sync::mpsc;

pub struct DeviceEventOutcome {
    pub activated: bool,
    pub retired: Vec<SessionKey>,
}

pub struct ShortcutController<R> {
    local_public_key: String,
    manager: ShortcutManager<R>,
    device: DeviceHandle,
}

impl<R: RouteManager> ShortcutController<R> {
    pub fn new(
        local_public_key: impl Into<String>,
        manager: ShortcutManager<R>,
        device: DeviceHandle,
    ) -> Self {
        Self {
            local_public_key: local_public_key.into(),
            manager,
            device,
        }
    }

    pub async fn receive_ticket(
        &mut self,
        ticket: ShortcutTicket,
        authenticated_sender: &str,
        now: u64,
        outbound: mpsc::Sender<RelayPacket>,
    ) -> Result<SessionKey> {
        let remote_public_key = ticket.remote_public_key.clone();
        let prepared = self.manager.receive_ticket(
            ticket,
            authenticated_sender,
            &self.local_public_key,
            now,
        )?;
        if prepared.already_present {
            return Ok(prepared.session);
        }
        if let Err(error) = self
            .device
            .prepare(prepared.session, prepared.keys, remote_public_key, outbound)
            .await
        {
            self.manager.fail(prepared.session)?;
            return Err(error);
        }
        self.manager.mark_handshaking(prepared.session)?;
        Ok(prepared.session)
    }

    pub fn handle_device_event(
        &mut self,
        event: &DeviceEvent,
        now: u64,
    ) -> Result<DeviceEventOutcome> {
        let activated = match event {
            DeviceEvent::AuthenticatedHandshake { session } => {
                self.manager.authenticated_handshake(*session, now)
            }
            DeviceEvent::HandshakeStarted { .. }
            | DeviceEvent::InnerPacket { .. }
            | DeviceEvent::MissingRoute { .. }
            | DeviceEvent::SessionFailed { .. } => Ok(false),
        }?;
        let retired = if activated {
            self.manager.retire_draining()
        } else {
            Vec::new()
        };
        Ok(DeviceEventOutcome { activated, retired })
    }

    pub fn expire(&mut self, now: u64) -> Result<Vec<SessionKey>> {
        self.manager.expire(now)
    }

    pub fn fail(&mut self, session: SessionKey) -> Result<bool> {
        self.manager.fail(session)
    }
}
