use std::ffi::{CStr, CString, c_void};
use std::intrinsics::copy_nonoverlapping;
use std::ptr::null_mut;
use std::str::FromStr;
use std::sync::{LazyLock, RwLock};

use tracing::{debug, error, info, trace, warn};
use winapi::um::{
    handleapi::INVALID_HANDLE_VALUE,
    libloaderapi::GetProcAddress,
    tlhelp32::{
        CreateToolhelp32Snapshot, MODULEENTRY32, Module32First, Module32Next, TH32CS_SNAPMODULE,
    },
};

const TARGET_ASSEMBLY: &str = "Assembly-CSharp";

pub static MONO_FUNCTION_PTRS: LazyLock<RwLock<MonoFunctions>> =
    LazyLock::new(|| RwLock::new(MonoFunctions::new()));

unsafe impl Send for AssemblyObjectInformation {}
unsafe impl Sync for AssemblyObjectInformation {}

pub static ASSEMBLIES: RwLock<Vec<AssemblyObjectInformation>> = RwLock::new(Vec::new());

pub type MonoGetRootDomain = extern "system" fn() -> *mut c_void;
pub type MonoThreadAttach = extern "system" fn(*mut c_void) -> *mut c_void;
pub type MonoAssemblyForEach =
    extern "system" fn(extern "system" fn(*mut c_void, *mut c_void), *mut c_void);
pub type MonoAssemblyGetImage = extern "system" fn(*mut c_void) -> *mut c_void;
pub type MonoImageGetName = extern "system" fn(*mut c_void) -> *mut c_void;
pub type MonoClassFromName =
    extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
pub type MonoClassGetMethodFromName =
    extern "system" fn(*mut c_void, *mut c_void, u32) -> *mut c_void;
pub type MonoCompileMethod = extern "system" fn(*mut c_void) -> c_void;

#[repr(C)]
#[derive(Debug)]
pub struct AssemblyObjectInformation {
    pub name: String,
    pub base: *mut c_void,
}

impl AssemblyObjectInformation {
    pub fn init_empty() -> Self {
        let zeroed = Self {
            name: String::new(),
            base: null_mut(),
        };

        zeroed
    }

    pub fn new(name: &str, base: *mut c_void) -> Self {
        Self {
            name: name.to_string(),
            base,
        }
    }
}

#[repr(C)]
pub struct MonoFunctions {
    pub mono_get_root_domain: MonoGetRootDomain,
    pub mono_thread_attach: MonoThreadAttach,
    pub mono_assembly_foreach: MonoAssemblyForEach,
    pub mono_assembly_get_image: MonoAssemblyGetImage,
    pub mono_image_get_name: MonoImageGetName,
    pub mono_class_from_name: MonoClassFromName,
    pub mono_class_get_method_from_name: MonoClassGetMethodFromName,
    pub mono_compile_method: MonoCompileMethod,
}

impl MonoFunctions {
    pub fn new() -> Self {
        let modules = get_modules();
        let mono_get_root_domain: MonoGetRootDomain =
            get_function_addr(modules[0].base_addr as _, "mono_get_root_domain");
        let mono_thread_attach: MonoThreadAttach =
            get_function_addr(modules[0].base_addr as _, "mono_thread_attach");
        let mono_assembly_foreach: MonoAssemblyForEach =
            get_function_addr(modules[0].base_addr as _, "mono_assembly_foreach");
        let mono_assembly_get_image: MonoAssemblyGetImage =
            get_function_addr(modules[0].base_addr as _, "mono_assembly_get_image");
        let mono_image_get_name: MonoAssemblyGetImage =
            get_function_addr(modules[0].base_addr as _, "mono_image_get_name");
        let mono_class_from_name: MonoClassFromName =
            get_function_addr(modules[0].base_addr as _, "mono_class_from_name");
        let mono_class_get_method_from_name: MonoClassGetMethodFromName =
            get_function_addr(modules[0].base_addr as _, "mono_class_get_method_from_name");
        let mono_compile_method: MonoCompileMethod =
            get_function_addr(modules[0].base_addr as _, "mono_compile_method");

        Self {
            mono_get_root_domain,
            mono_thread_attach,
            mono_assembly_foreach,
            mono_assembly_get_image,
            mono_image_get_name,
            mono_class_from_name,
            mono_class_get_method_from_name,
            mono_compile_method,
        }
    }
}

pub const WANTS_MODULES: [&'static str; 1] = [
    // "ntdll.dll",
    // "user32.dll",
    // "kernel32.dll",
    "mono-2.0-bdwgc.dll",
];

#[macro_export]
macro_rules! close_handle {
    ($handle:expr) => {
        if $handle != winapi::um::handleapi::INVALID_HANDLE_VALUE
            && $handle != core::ptr::null_mut()
        {}
    };
}

pub fn charptr_to_string(a: *mut i8) -> String {
    unsafe { CStr::from_ptr(a).to_string_lossy().to_string() }
}

#[repr(C)]
#[derive(Debug)]
pub struct ProcessModule {
    pub name: String,
    pub base_addr: *mut u8,
}

pub fn get_modules() -> Vec<ProcessModule> {
    let mut module: MODULEENTRY32 = unsafe { core::mem::zeroed() };
    module.dwSize = size_of::<MODULEENTRY32>() as _;

    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0x00) };
    if snapshot_handle == INVALID_HANDLE_VALUE {
        error!("failed to get snapshot handle");
    }

    if unsafe { !(Module32First(snapshot_handle, &mut module) == 0x01) } {
        error!("failed to get first module");
    }

    let mut loaded_modules = Vec::new();

    loop {
        let curr_module = charptr_to_string(module.szModule.as_ptr() as _).to_lowercase();
        let base = module.modBaseAddr;
        // trace!("found: {:#?} @ {:016x?}", curr_module, base);

        if WANTS_MODULES.contains(&curr_module.as_ref()) {
            let mod_info = ProcessModule {
                name: curr_module.clone(),
                base_addr: base,
            };

            loaded_modules.push(mod_info);
        }

        if unsafe { Module32Next(snapshot_handle, &mut module) != 0x01 } {
            close_handle!(snapshot_handle);
            break;
        }
    }

    close_handle!(snapshot_handle);
    info!("found: {:#?}", loaded_modules);

    loaded_modules
}

pub fn load_assembly() {
    let fns = MONO_FUNCTION_PTRS.read().unwrap();
    let thread_handle = (fns.mono_thread_attach)((fns.mono_get_root_domain)());
    info!("thread handle: {:016x?}", thread_handle);

    (fns.mono_assembly_foreach)(assembly_callback as _, null_mut());

    let assemblies_guard = ASSEMBLIES.read().unwrap();
    debug!("found: {:?}", assemblies_guard);

    drop(assemblies_guard);
}

pub fn strlen(ptr: *const u8) -> usize {
    let mut n = 0;

    while unsafe { (*ptr.byte_add(n)) != 0x00 } {
        n += 1;
    }

    n
}

pub fn ptr_to_string(ptr: *const u8) -> String {
    let length = strlen(ptr);
    let mut data: Vec<u8> = Vec::with_capacity(length);
    unsafe { data.set_len(length) };

    unsafe { copy_nonoverlapping(ptr, data.as_mut_ptr(), length) };

    String::from_utf8(data).unwrap()
}

#[unsafe(no_mangle)]
pub extern "system" fn assembly_callback(mono_assembly: *mut c_void, _: *mut c_void) {
    let fns = MONO_FUNCTION_PTRS.read().unwrap();

    let mono_assembly_image = (fns.mono_assembly_get_image)(mono_assembly);
    let assembly_name_raw: *mut u8 = (fns.mono_image_get_name)(mono_assembly_image) as *mut u8;
    let assembly_name = ptr_to_string(assembly_name_raw);

    trace!("-'{}'", assembly_name);
    if assembly_name == TARGET_ASSEMBLY {
        info!("");
        info!("\t\t {} @ {:016x?}\n", assembly_name, mono_assembly);

        let assembly_info = AssemblyObjectInformation::new(&assembly_name, mono_assembly);
        let mut assemblies_guard = ASSEMBLIES.write().unwrap();
        assemblies_guard.push(assembly_info);

        drop(assemblies_guard);
    }
}

pub fn get_class() {
    let assemblies_guard = ASSEMBLIES.read().unwrap();
    if assemblies_guard.is_empty() {
        warn!("'ASSEMBLIES' global not initialized");
        return;
    }

    let fns = MONO_FUNCTION_PTRS.read().unwrap();
    // let class_name = 

    // let maybe_class = (fns.mono_class_from_name)()

}

pub fn get_function_addr<T>(handle: *mut c_void, fn_name: &str) -> T {
    let cstr_ptr = cstr_from_str(fn_name);
    let farproc = unsafe { GetProcAddress(handle as _, cstr_ptr.as_ptr()) };
    let resolved = unsafe { std::mem::transmute_copy(&farproc) };

    trace!(
        "function '{}': {:016x?}",
        fn_name,
        std::ptr::from_ref(&resolved)
    );
    resolved
}

pub fn cstr_from_str(s: &str) -> CString {
    CString::from_str(s).unwrap()
}
