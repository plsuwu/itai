use core::ffi::CStr;
use core::ptr::null_mut;
use std::ffi::CString;
use std::str::FromStr;

use thiserror::Error;
use widestring::WideCString;
use winapi::shared::minwindef::{DWORD, FARPROC, LPCVOID, LPVOID, MAX_PATH};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{
    HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS,
};

use crate::inject::unsafe_wrapped::{
    SafeCreateRemoteThread, SafeCreateToolhelp32Snapshot, SafeGetModuleHandle, SafeGetProcAddress,
    SafeOpenProcess, SafeProcess32First, SafeProcess32Next, SafeVirtualAllocEx,
    SafeWriteProcessMemory,
};
use crate::{api_call_err, close_handle};

pub type InjectorResult<T> = core::result::Result<T, InjectorError>;

#[derive(Debug, Error)]
pub enum InjectorError {
    #[error("API call '{0}' failed: {1:016x?}")]
    ApiCallFailed(&'static str, DWORD),
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcessInformation {
    pub proc_id: DWORD,
    pub proc_handle: HANDLE,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ThreadInformation {
    pub thread_id: DWORD,
    pub thread_handle: HANDLE,
}

pub fn charptr_to_string(a: *mut i8) -> String {
    unsafe { CStr::from_ptr(a).to_string_lossy().to_string() }
}

pub fn string_to_charptr(s: &str) -> *mut i8 {
    s.as_ptr() as _
}

pub fn get_load_library_addr() -> InjectorResult<FARPROC> {
    let module_name = CString::from_str("kernel32.dll").unwrap();
    let function_name = CString::from_str("LoadLibraryW").unwrap();
    let module_handle = SafeGetModuleHandle(module_name.as_ptr());

    let proc_addr = SafeGetProcAddress(module_handle, function_name.as_ptr());

    if proc_addr.is_null() {
        return api_call_err!("GetProcAddress");
    }

    Ok(proc_addr)
}

pub fn inject_dll(
    proc_info: &ProcessInformation,
    dll_name: &WideCString,
) -> InjectorResult<LPVOID> {
    let dll_name_ptr = dll_name.as_ptr();
    let load_library_w = get_load_library_addr()?;

    let data_len = dll_name.len() * 2;

    println!("LoadLibaryW: {:016x?}", load_library_w);

    let allocation = SafeVirtualAllocEx(
        proc_info.proc_handle,
        null_mut(),
        data_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if allocation.is_null() {
        return api_call_err!("VirtualAllocEx");
    }

    println!("allocated {} bytes @ {:016x?}", data_len, allocation);

    let mut bytes_written = 0;
    if !SafeWriteProcessMemory(
        proc_info.proc_handle,
        allocation,
        dll_name_ptr as _,
        data_len,
        &mut bytes_written,
    ) {
        println!("failed: wrote {} of {} bytes", bytes_written, data_len,);
        return api_call_err!("WriteProcessMemory");
    }

    println!("wrote {} bytes to {:?}", bytes_written, allocation);
    Ok(allocation)
}

pub fn exec_thread(
    allocation: LPVOID,
    proc_info: &ProcessInformation,
) -> InjectorResult<ThreadInformation> {
    let load_library_addr = get_load_library_addr()?;
    let mut thread_id = 0;
    let start_routine =
        unsafe { core::mem::transmute::<_, LPTHREAD_START_ROUTINE>(load_library_addr) };

    let thread_handle = SafeCreateRemoteThread(
        proc_info.proc_handle,
        null_mut(),
        0,
        start_routine,
        allocation,
        0,
        &mut thread_id,
    );

    if thread_handle.is_null() {
        return api_call_err!("CreateRemoteThread");
    }

    println!(
        "thread create ok: HANDLE->{:?},id->{}",
        thread_handle, thread_id
    );

    Ok(ThreadInformation {
        thread_id,
        thread_handle,
    })
}

pub fn get_remote_process_handle(procname: &str) -> InjectorResult<ProcessInformation> {
    let procname = procname.to_lowercase();
    let mut proc: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    proc.dwSize = size_of::<PROCESSENTRY32>() as _;

    // let mut proc: PROCESSENTRY32 = PROCESSENTRY32 {
    //     dwSize: size_of::<PROCESSENTRY32>() as _,
    //     cntUsage: 0,
    //     th32ProcessID: 0,
    //     th32DefaultHeapID: 0,
    //     th32ModuleID: 0,
    //     cntThreads: 0,
    //     th32ParentProcessID: 0,
    //     pcPriClassBase: 0,
    //     dwFlags: 0,
    //     szExeFile: [0; MAX_PATH],
    // };

    let snapshot_handle = SafeCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x00);
    if snapshot_handle == INVALID_HANDLE_VALUE {
        return api_call_err!("CreateToolhelp32Snapshot");
    }

    if !SafeProcess32First(snapshot_handle, &mut proc) {
        close_handle!(snapshot_handle);
        return api_call_err!("Process32First");
    }

    let mut result = ProcessInformation::default();

    loop {
        let curr_proc = charptr_to_string(proc.szExeFile.as_ptr() as _).to_lowercase();
        println!("curr->{:?};wants->{:?}", curr_proc, procname);
        if curr_proc.eq(&procname) {
            result.proc_id = proc.th32ProcessID;
            result.proc_handle = SafeOpenProcess(PROCESS_ALL_ACCESS, 0x00, proc.th32ProcessID);
            if result.proc_handle == INVALID_HANDLE_VALUE || result.proc_handle == null_mut() {
                close_handle!(snapshot_handle);
                return api_call_err!("OpenProcess");
            }

            break;
        }

        if !SafeProcess32Next(snapshot_handle, &mut proc) {
            close_handle!(snapshot_handle);
            return api_call_err!("Process32Next");
        }
    }

    close_handle!(snapshot_handle);
    Ok(result)
}
