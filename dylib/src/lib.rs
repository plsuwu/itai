use std::thread;

use tracing::{debug, info, trace};

pub mod console;
pub mod enumeration;
pub mod msgbox;

pub fn runner() {
    console::setup();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true)
        .without_time()
        .init();

    debug!("hello from allocated console");

    enumeration::get_modules();
    enumeration::load_assembly();
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_: *mut u8, reason: u32, _: *mut u8) -> i32 {
    match reason {
        1 => runner(),
        _ => (),
    }

    0
}
