#![allow(unused_assignments, dead_code, unused_macros, unused_imports)]

mod inject;

use std::{thread::sleep, time::Duration};

use widestring::WideCString;
use winapi::um::synchapi::WaitForSingleObject;

use crate::inject::injector::{self, InjectorResult};

const FILENAME: &str =
    "C:\\Users\\Peas\\Documents\\itai\\target\\debug\\dylib.dll";

const TARGET_PROCESS_NAME: &str = "hollow knight silksong.exe";

fn main() -> InjectorResult<()> {
    let filename = WideCString::from_str(FILENAME).unwrap();
    let proc_info = injector::get_remote_process_handle(TARGET_PROCESS_NAME)?;
    let allocation = injector::inject_dll(&proc_info, &filename)?;
    let thread_handle = injector::exec_thread(allocation, &proc_info)?;

    println!("remote_thread_handle: {:?}", thread_handle);
    Ok(())
}
