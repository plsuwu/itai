use std::thread;

use tracing::debug;
use winapi::shared::minwindef::DWORD;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::STD_OUTPUT_HANDLE;
use winapi::um::wincon::{ENABLE_VIRTUAL_TERMINAL_PROCESSING, FreeConsole};
use winapi::um::winuser::{GetAsyncKeyState, VK_CONTROL};

use crate::poperr;

pub const ERROR_TITLE: &str = "ERR";
pub const VIRT_KEYCODES: [i32; 2] = [VK_CONTROL, 0x43];

pub fn setup() {
    unsafe {
        // i couldn't get the console to attach without calling `FreeConsole` first; microsoft docs
        // seem to indicate this is intended behaviour but who would know really
        if FreeConsole() == 0x00 {
            poperr!("couldnt free current console");
        }

        if AllocConsole() == 0x00 {
            poperr!("couldnt allocate new console");
        }

        let stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: DWORD = 0;
        if GetConsoleMode(stdout_handle, &mut mode) != 0 {
            SetConsoleMode(stdout_handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}
