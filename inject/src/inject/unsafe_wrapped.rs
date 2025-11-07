#![allow(non_snake_case)]

use widestring::WideCString;
use winapi::{
    shared::{
        basetsd::{PSIZE_T, SIZE_T},
        minwindef::{DWORD, FARPROC, HMODULE, LPCVOID, LPDWORD, LPVOID},
        ntdef::{BOOLEAN, LPCSTR, LPCWSTR},
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        libloaderapi::{GetModuleHandleA, GetModuleHandleW, GetProcAddress},
        memoryapi::{VirtualAllocEx, WriteProcessMemory},
        minwinbase::{LPSECURITY_ATTRIBUTES, LPTHREAD_START_ROUTINE},
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        tlhelp32::{CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next},
        winnt::HANDLE,
    },
};

#[macro_export]
macro_rules! api_call_err {
    ($api:expr) => {
        Err(crate::inject::injector::InjectorError::ApiCallFailed(
            $api,
            crate::inject::unsafe_wrapped::SafeGetLastError(),
        ))
    };
}

#[macro_export]
macro_rules! close_handle {
    ($handle:expr) => {
        if $handle != winapi::um::handleapi::INVALID_HANDLE_VALUE
            && $handle != core::ptr::null_mut()
        {
            crate::inject::unsafe_wrapped::SafeCloseHandle($handle);
        }
    };
}

pub fn SafeVirtualAllocEx(
    process_handle: HANDLE,
    address: LPVOID,
    size: SIZE_T,
    alloc_type: DWORD,
    protection: DWORD,
) -> LPVOID {
    unsafe { VirtualAllocEx(process_handle, address, size, alloc_type, protection) }
}

pub fn SafeGetProcAddress(module_handle: HMODULE, fn_name: LPCSTR) -> FARPROC {
    unsafe { GetProcAddress(module_handle, fn_name as _) }
}

pub fn SafeGetModuleHandle(module_name: LPCSTR) -> HMODULE {
    unsafe { GetModuleHandleA(module_name) }
}

pub fn SafeCreateToolhelp32Snapshot(f: DWORD, p: DWORD) -> HANDLE {
    unsafe { CreateToolhelp32Snapshot(f, p) }
}

pub fn SafeGetLastError() -> DWORD {
    unsafe { GetLastError() }
}

pub fn SafeProcess32First(s: HANDLE, p: *mut PROCESSENTRY32) -> bool {
    unsafe { Process32First(s, p) == 0x01 }
}

pub fn SafeProcess32Next(s: HANDLE, p: *mut PROCESSENTRY32) -> bool {
    unsafe { Process32Next(s, p) == 0x01 }
}

pub fn SafeOpenProcess(a: DWORD, i: i32, p: DWORD) -> HANDLE {
    unsafe { OpenProcess(a, i, p) }
}

pub fn SafeCloseHandle(h: HANDLE) -> bool {
    unsafe { CloseHandle(h) == 0x01 }
}

pub fn SafeCreateRemoteThread(
    process: HANDLE,
    attrs: LPSECURITY_ATTRIBUTES,
    stack_size: SIZE_T,
    start_addr: LPTHREAD_START_ROUTINE,
    param: LPVOID,
    flags: DWORD,
    thread_id: LPDWORD,
) -> HANDLE {
    unsafe {
        CreateRemoteThread(
            process, attrs, stack_size, start_addr, param, flags, thread_id,
        )
    }
}

pub fn SafeWriteProcessMemory(
    process: HANDLE,
    base_addr: LPVOID,
    data_buffer: LPCVOID,
    size: SIZE_T,
    bytes_written: PSIZE_T,
) -> bool {
    unsafe { WriteProcessMemory(process, base_addr, data_buffer, size, bytes_written) == 0x01 }
}
