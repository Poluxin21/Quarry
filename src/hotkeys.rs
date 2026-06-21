//! Hotkeys globais (funcionam mesmo com o jogo em foco) via `RegisterHotKey`.
//!
//! Uma thread dedicada registra os atalhos com hwnd nulo e roda um loop
//! `GetMessageW`; cada `WM_HOTKEY` e enviado por canal para a GUI, que consome
//! em `poll()` a cada frame. Combinacao fixa Ctrl+Alt+F1..F4 (modificadores
//! reduzem conflito com teclas do jogo).

use std::sync::mpsc::{channel, Receiver, Sender};

use windows::Win32::UI::Input::KeyboardAndMouse::{
    RegisterHotKey, HOT_KEY_MODIFIERS, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT,
};
use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

/// IDs dos atalhos (tambem usados como id do RegisterHotKey).
pub const HK_FREEZE_ALL: u32 = 1;
pub const HK_UNFREEZE_ALL: u32 = 2;
pub const HK_AA_ENABLE: u32 = 3;
pub const HK_AA_DISABLE: u32 = 4;

/// Texto de ajuda para exibir na GUI.
pub const LEGEND: &str =
    "Atalhos globais: Ctrl+Alt+F1 congelar tudo · F2 descongelar · F3 AA Enable · F4 AA Disable";

/// Gerencia a thread de hotkeys e entrega os eventos recebidos.
pub struct HotkeyManager {
    rx: Receiver<u32>,
}

impl HotkeyManager {
    pub fn start() -> Self {
        let (tx, rx) = channel();
        std::thread::spawn(move || run(tx));
        Self { rx }
    }

    /// Devolve (sem bloquear) os IDs de hotkey disparados desde a ultima chamada.
    pub fn poll(&self) -> Vec<u32> {
        self.rx.try_iter().collect()
    }
}

fn run(tx: Sender<u32>) {
    unsafe {
        let modifiers: HOT_KEY_MODIFIERS = MOD_CONTROL | MOD_ALT | MOD_NOREPEAT;
        // F1..F4 = 0x70..0x73
        let binds = [
            (HK_FREEZE_ALL, 0x70u32),
            (HK_UNFREEZE_ALL, 0x71),
            (HK_AA_ENABLE, 0x72),
            (HK_AA_DISABLE, 0x73),
        ];
        for (id, vk) in binds {
            let _ = RegisterHotKey(None, id as i32, modifiers, vk);
        }

        let mut msg = MSG::default();
        // hwnd nulo: as mensagens chegam na fila desta thread.
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if msg.message == WM_HOTKEY {
                let _ = tx.send(msg.wParam.0 as u32);
            }
        }
    }
}
