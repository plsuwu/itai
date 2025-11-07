use std::ffi::CString;
use std::str::FromStr;

use winapi::um::winuser::MB_ICONERROR;
use winapi::um::winuser::{MB_ICONINFORMATION, MB_OK, MessageBoxA};

#[macro_export]
macro_rules! popmsg {
    ($t:expr, $c:expr) => {
        crate::msgbox::MsgBox::new($t, $c).pop();
    };
}

#[macro_export]
macro_rules! poperr {
    ($c:expr) => {
        use winapi::um::errhandlingapi::GetLastError;
        crate::msgbox::MsgBox::new(ERROR_TITLE, &format!("{}: {:016x?}", $c, GetLastError())).err();
    };
}

#[derive(Debug)]
pub struct MsgBox {
    pub title: CString,
    pub content: CString,
    _title: String,
    _content: String,
}

impl MsgBox {
    pub fn new(title: &str, content: &str) -> Self {
        Self {
            _title: title.to_string(),
            _content: content.to_string(),
            title: CString::from_str(title).unwrap(),
            content: CString::from_str(content).unwrap(),
        }
    }

    pub fn pop(&self) {
        unsafe {
            MessageBoxA(
                std::ptr::null_mut(),
                self.content.as_ptr(),
                self.title.as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }

    pub fn err(&self) {
        unsafe {
            MessageBoxA(
                std::ptr::null_mut(),
                self.content.as_ptr(),
                self.title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}
