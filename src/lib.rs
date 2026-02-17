use std::{env, mem, ptr};

use windows::{
    Win32::Foundation::*,
    Win32::System::Diagnostics::Debug::*,
    Win32::System::Memory::*,
    Win32::System::Threading::*,
    core::{PCSTR, PSTR},
};

// Only compile on x86-64 architecture
#[cfg(not(target_arch = "x86_64"))]
compile_error!("This crate only supports x86-64 target architecture");

#[cfg(not(target_os = "windows"))]
compile_error!("This crate only supports Windows target OS");

mod ext;
use ext::*;
mod types;
use types::*;

pub struct InjectedProcess {
    pub pid: u32,
    pub handle: HANDLE,
    pub thread_handle: HANDLE,
}

impl Drop for InjectedProcess {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
            let _ = CloseHandle(self.thread_handle);
        }
    }
}

#[derive(Debug)]
pub enum InjectionError {
    InvalidPayload(String),
    ProcessCreationFailed(String),
    MemoryAllocationFailed(String),
    MemoryReadFailed(String),
    MemoryWriteFailed(String),
    ContextOperationFailed(String),
    ResumeFailed(String),
    ImportResolutionFailed(String),
    RelocationFailed(String),
}

impl std::fmt::Display for InjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectionError::InvalidPayload(msg) => write!(f, "Invalid payload: {}", msg),
            InjectionError::ProcessCreationFailed(msg) => {
                write!(f, "Process creation failed: {}", msg)
            }
            InjectionError::MemoryAllocationFailed(msg) => {
                write!(f, "Memory allocation failed: {}", msg)
            }
            InjectionError::MemoryReadFailed(msg) => write!(f, "Memory read failed: {}", msg),
            InjectionError::MemoryWriteFailed(msg) => write!(f, "Memory write failed: {}", msg),
            InjectionError::ContextOperationFailed(msg) => {
                write!(f, "Context operation failed: {}", msg)
            }
            InjectionError::ResumeFailed(msg) => write!(f, "Failed to resume thread: {}", msg),
            InjectionError::ImportResolutionFailed(msg) => {
                write!(f, "Import resolution failed: {}", msg)
            }
            InjectionError::RelocationFailed(msg) => write!(f, "Relocation failed: {}", msg),
        }
    }
}

impl std::error::Error for InjectionError {}

#[derive(Default)]
struct ProcessInfo {
    startup: STARTUPINFOA,
    process: PROCESS_INFORMATION,
}

impl ProcessInfo {
    /// clean up process resources on error
    unsafe fn cleanup(&self) {
        unsafe {
            let _ = TerminateProcess(self.process.hProcess, 1);
            let _ = CloseHandle(self.process.hThread);
            let _ = CloseHandle(self.process.hProcess);
        }
    }
}

/// Inject payload bytes into a duplicate of the current process
///
/// # Arguments
/// * `payload` - The raw bytes of a PE executable to inject
///
/// # Returns
/// * `Ok(InjectedProcess)` - Information about the injected process
/// * `Err(InjectionError)` - If injection fails
pub fn inject_payload(payload: &[u8]) -> Result<InjectedProcess, InjectionError> {
    unsafe { inject_payload_impl(payload) }
}

/// Create a clone of our current process in suspended mode for later injection
unsafe fn create_suspended_self() -> Result<ProcessInfo, InjectionError> {
    unsafe {
        let mut info = ProcessInfo::default();

        let current_exe = env::current_exe().map_err(|e| {
            InjectionError::ProcessCreationFailed(format!("Failed to get current exe: {}", e))
        })?;

        let exe_path = current_exe.to_string_lossy();
        let mut cmd_line = format!("{}\0", exe_path).into_bytes();

        CreateProcessA(
            PCSTR::null(),
            Some(PSTR::from_raw(cmd_line.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0x4), // CREATE_SUSPENDED
            None,
            PCSTR::null(),
            &mut info.startup,
            &mut info.process,
        )
        .map_err(|e| {
            InjectionError::ProcessCreationFailed(format!("CreateProcessA failed: {}", e))
        })?;

        Ok(info)
    }
}

unsafe fn get_nt_headers(payload_data: &[u8]) -> Result<(ImageNtHeaders64, usize), InjectionError> {
    unsafe {
        if payload_data.len() < mem::size_of::<ImageDosHeader>() {
            return Err(InjectionError::InvalidPayload(
                "File too small for DOS header".into(),
            ));
        }

        let dos_header = ptr::read(payload_data.as_ptr() as *const ImageDosHeader);

        if dos_header.e_magic != 0x5A4D {
            return Err(InjectionError::InvalidPayload(
                "Invalid DOS signature (expected MZ)".into(),
            ));
        }

        let nt_headers_offset = dos_header.e_lfanew as usize;
        if payload_data.len() < nt_headers_offset + mem::size_of::<ImageNtHeaders64>() {
            return Err(InjectionError::InvalidPayload(
                "NT headers out of bounds".into(),
            ));
        }

        let nt_headers =
            ptr::read(payload_data.as_ptr().add(nt_headers_offset) as *const ImageNtHeaders64);

        if nt_headers.signature != 0x4550 {
            return Err(InjectionError::InvalidPayload(
                "Invalid PE signature".into(),
            ));
        }

        // 64 bit validation
        if nt_headers.file_header.machine != 0x8664 {
            return Err(InjectionError::InvalidPayload(
                "Not a 64-bit executable".into(),
            ));
        }

        Ok((nt_headers, nt_headers_offset))
    }
}

unsafe fn rva_to_file_offset(
    payload_data: &[u8],
    rva: u32,
    nt_headers: &ImageNtHeaders64,
    nt_headers_offset: usize,
) -> Option<usize> {
    unsafe {
        let section_headers_offset = nt_headers_offset
            + mem::size_of::<u32>()
            + mem::size_of::<ImageFileHeader>()
            + nt_headers.file_header.size_of_optional_header as usize;

        for i in 0..nt_headers.file_header.number_of_sections {
            let section_offset =
                section_headers_offset + (i as usize * mem::size_of::<ImageSectionHeader>());

            if section_offset + mem::size_of::<ImageSectionHeader>() > payload_data.len() {
                return None;
            }

            let section =
                ptr::read(payload_data.as_ptr().add(section_offset) as *const ImageSectionHeader);

            let section_start = section.virtual_address;
            let section_end = section.virtual_address.saturating_add(section.virtual_size);

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section.virtual_address;
                let file_offset = section.pointer_to_raw_data as usize + offset_in_section as usize;

                if file_offset < payload_data.len() {
                    return Some(file_offset);
                }
            }
        }
        None
    }
}

unsafe fn read_process_memory_checked(
    process: HANDLE,
    address: *const std::ffi::c_void,
    buffer: *mut std::ffi::c_void,
    size: usize,
    context: &str,
) -> Result<usize, InjectionError> {
    unsafe {
        let mut bytes_read: usize = 0;
        ReadProcessMemory(process, address, buffer, size, Some(&mut bytes_read))
            .map_err(|e| InjectionError::MemoryReadFailed(format!("{}: {}", context, e)))?;

        if bytes_read != size {
            return Err(InjectionError::MemoryReadFailed(format!(
                "{}: expected {} bytes, read {}",
                context, size, bytes_read
            )));
        }
        Ok(bytes_read)
    }
}

unsafe fn write_process_memory_checked(
    process: HANDLE,
    address: *const std::ffi::c_void,
    buffer: *const std::ffi::c_void,
    size: usize,
    context: &str,
) -> Result<usize, InjectionError> {
    unsafe {
        let mut bytes_written: usize = 0;
        WriteProcessMemory(process, address, buffer, size, Some(&mut bytes_written))
            .map_err(|e| InjectionError::MemoryWriteFailed(format!("{}: {}", context, e)))?;

        if bytes_written != size {
            return Err(InjectionError::MemoryWriteFailed(format!(
                "{}: expected {} bytes, wrote {}",
                context, size, bytes_written
            )));
        }
        Ok(bytes_written)
    }
}

unsafe fn inject_payload_impl(payload: &[u8]) -> Result<InjectedProcess, InjectionError> {
    unsafe {
        let info = create_suspended_self()?;

        // ensure we clean up afterwards no matter the result
        match inject_payload_inner(payload, &info) {
            Ok(result) => Ok(result),
            Err(e) => {
                info.cleanup();
                Err(e)
            }
        }
    }
}

unsafe fn inject_payload_inner(
    payload: &[u8],
    info: &ProcessInfo,
) -> Result<InjectedProcess, InjectionError> {
    unsafe {
        // get thread context
        #[repr(C, align(16))]
        struct AlignedContext {
            context: CONTEXT,
        }
        let mut aligned_context = AlignedContext {
            context: std::mem::zeroed(),
        };
        aligned_context.context.ContextFlags = CONTEXT_FLAGS(0x10000B);

        let ctx_result = GetThreadContext(
            info.process.hThread,
            &mut aligned_context.context as *mut CONTEXT,
        );
        if ctx_result == 0 {
            return Err(InjectionError::ContextOperationFailed(format!(
                "GetThreadContext failed: {:?}",
                GetLastError()
            )));
        }

        // read image base from PEB
        let peb_address = aligned_context.context.Rdx;
        let image_base_offset: u64 = 0x10;
        let mut image_base: usize = 0;

        read_process_memory_checked(
            info.process.hProcess,
            (peb_address + image_base_offset) as *const std::ffi::c_void,
            &mut image_base as *mut _ as *mut std::ffi::c_void,
            mem::size_of::<usize>(),
            "Reading PEB image base",
        )?;

        // parse and validate payload
        let (nt_headers, nt_headers_offset) = get_nt_headers(payload)?;

        // allocate memory for payload (don't unmap to preserve loader structures)
        let payload_image_base = VirtualAllocEx(
            info.process.hProcess,
            Some(nt_headers.optional_header.image_base as *const std::ffi::c_void),
            nt_headers.optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        let new_image_base = if payload_image_base.is_null() {
            // try alternate address
            let alternate = VirtualAllocEx(
                info.process.hProcess,
                None,
                nt_headers.optional_header.size_of_image as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if alternate.is_null() {
                return Err(InjectionError::MemoryAllocationFailed(format!(
                    "VirtualAllocEx failed for {} bytes: {:?}",
                    nt_headers.optional_header.size_of_image,
                    GetLastError()
                )));
            }
            alternate
        } else {
            payload_image_base
        };

        // write PE headers
        write_process_memory_checked(
            info.process.hProcess,
            new_image_base,
            payload.as_ptr() as *const std::ffi::c_void,
            nt_headers.optional_header.size_of_headers as usize,
            "Writing PE headers",
        )?;

        write_sections(
            payload,
            info,
            &nt_headers,
            nt_headers_offset,
            new_image_base,
        )?;

        // process relocations if needed
        let delta = new_image_base as i64 - nt_headers.optional_header.image_base as i64;
        if delta != 0 {
            process_relocations(
                payload,
                info,
                &nt_headers,
                nt_headers_offset,
                new_image_base,
                delta,
            )?;
        }

        // resolve imports
        resolve_imports(
            payload,
            info,
            &nt_headers,
            nt_headers_offset,
            new_image_base,
        )?;

        // update PEB with new image base
        let new_base_value = new_image_base as usize;
        write_process_memory_checked(
            info.process.hProcess,
            (peb_address + image_base_offset) as *mut std::ffi::c_void,
            &new_base_value as *const usize as *const std::ffi::c_void,
            mem::size_of::<usize>(),
            "Updating PEB image base",
        )?;

        // set entry point
        let entry_point =
            new_image_base as u64 + nt_headers.optional_header.address_of_entry_point as u64;

        aligned_context.context.Rip = entry_point;
        aligned_context.context.Rcx = peb_address;

        let set_context_result = SetThreadContext(
            info.process.hThread,
            &aligned_context.context as *const CONTEXT,
        );

        if set_context_result == 0 {
            return Err(InjectionError::ContextOperationFailed(format!(
                "SetThreadContext failed: {:?}",
                GetLastError()
            )));
        }

        // resume thread
        let resume_result = ResumeThread(info.process.hThread);
        if resume_result == u32::MAX {
            return Err(InjectionError::ResumeFailed(format!(
                "ResumeThread failed: {:?}",
                GetLastError()
            )));
        }

        Ok(InjectedProcess {
            pid: info.process.dwProcessId,
            handle: info.process.hProcess,
            thread_handle: info.process.hThread,
        })
    }
}

unsafe fn write_sections(
    payload: &[u8],
    info: &ProcessInfo,
    nt_headers: &ImageNtHeaders64,
    nt_headers_offset: usize,
    new_image_base: *mut std::ffi::c_void,
) -> Result<(), InjectionError> {
    unsafe {
        let section_headers_offset = nt_headers_offset
            + mem::size_of::<u32>()
            + mem::size_of::<ImageFileHeader>()
            + nt_headers.file_header.size_of_optional_header as usize;

        for i in 0..nt_headers.file_header.number_of_sections {
            let section_offset =
                section_headers_offset + (i as usize * mem::size_of::<ImageSectionHeader>());

            if section_offset + mem::size_of::<ImageSectionHeader>() > payload.len() {
                return Err(InjectionError::InvalidPayload(format!(
                    "Section header {} out of bounds",
                    i
                )));
            }

            let section =
                ptr::read(payload.as_ptr().add(section_offset) as *const ImageSectionHeader);
            let section_name = std::str::from_utf8(&section.name)
                .unwrap_or("unknown")
                .trim_end_matches('\0');

            if section.size_of_raw_data == 0 {
                continue;
            }

            // validate section data is within payload bounds
            let raw_data_end =
                section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
            if raw_data_end > payload.len() {
                return Err(InjectionError::InvalidPayload(format!(
                    "Section '{}' data out of bounds",
                    section_name
                )));
            }

            let section_dest = (new_image_base as usize + section.virtual_address as usize)
                as *mut std::ffi::c_void;
            let section_src = payload.as_ptr().add(section.pointer_to_raw_data as usize);

            write_process_memory_checked(
                info.process.hProcess,
                section_dest,
                section_src as *const std::ffi::c_void,
                section.size_of_raw_data as usize,
                &format!("Writing section '{}'", section_name),
            )?;
        }

        Ok(())
    }
}

unsafe fn process_relocations(
    payload: &[u8],
    info: &ProcessInfo,
    nt_headers: &ImageNtHeaders64,
    nt_headers_offset: usize,
    new_image_base: *mut std::ffi::c_void,
    delta: i64,
) -> Result<(), InjectionError> {
    unsafe {
        let reloc_dir = &nt_headers.optional_header.data_directory[DIR_ENTRY_BASERELOC];

        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            // no relocations needed
            return Ok(());
        }

        let mut reloc_rva = reloc_dir.virtual_address;
        let reloc_end_rva = reloc_rva + reloc_dir.size;
        let mut processed_count = 0;

        while reloc_rva < reloc_end_rva {
            let reloc_file_offset =
                rva_to_file_offset(payload, reloc_rva, nt_headers, nt_headers_offset).ok_or_else(
                    || {
                        InjectionError::RelocationFailed(format!(
                            "Failed to convert relocation RVA 0x{:X} to file offset",
                            reloc_rva
                        ))
                    },
                )?;

            if reloc_file_offset + mem::size_of::<ImageBaseRelocation>() > payload.len() {
                return Err(InjectionError::RelocationFailed(
                    "Relocation block out of bounds".into(),
                ));
            }

            let reloc_block =
                ptr::read(payload.as_ptr().add(reloc_file_offset) as *const ImageBaseRelocation);

            if reloc_block.size_of_block == 0 {
                break;
            }

            let num_entries =
                (reloc_block.size_of_block as usize - mem::size_of::<ImageBaseRelocation>()) / 2;
            let entries_offset = reloc_file_offset + mem::size_of::<ImageBaseRelocation>();

            if entries_offset + num_entries * 2 > payload.len() {
                return Err(InjectionError::RelocationFailed(
                    "Relocation entries out of bounds".into(),
                ));
            }

            let entries_ptr = payload.as_ptr().add(entries_offset) as *const u16;

            for i in 0..num_entries {
                let entry = *entries_ptr.add(i);
                let reloc_type = (entry >> 12) as u16;
                let offset = (entry & 0xFFF) as u32;

                if reloc_type == IMAGE_REL_BASED_DIR64 {
                    let patch_addr = new_image_base as usize
                        + reloc_block.virtual_address as usize
                        + offset as usize;
                    let mut original_value: u64 = 0;

                    read_process_memory_checked(
                        info.process.hProcess,
                        patch_addr as *const std::ffi::c_void,
                        &mut original_value as *mut _ as *mut std::ffi::c_void,
                        8,
                        &format!("Reading relocation at 0x{:X}", patch_addr),
                    )?;

                    let new_value = (original_value as i64 + delta) as u64;

                    write_process_memory_checked(
                        info.process.hProcess,
                        patch_addr as *mut std::ffi::c_void,
                        &new_value as *const _ as *const std::ffi::c_void,
                        8,
                        &format!("Writing relocation at 0x{:X}", patch_addr),
                    )?;

                    processed_count += 1;
                }
            }

            reloc_rva += reloc_block.size_of_block;
        }

        Ok(())
    }
}

unsafe fn resolve_imports(
    payload: &[u8],
    info: &ProcessInfo,
    nt_headers: &ImageNtHeaders64,
    nt_headers_offset: usize,
    new_image_base: *mut std::ffi::c_void,
) -> Result<(), InjectionError> {
    unsafe {
        let import_dir = &nt_headers.optional_header.data_directory[DIR_ENTRY_IMPORT];

        if import_dir.virtual_address == 0 {
            return Ok(()); // no imports
        }

        let mut import_desc_rva = import_dir.virtual_address;

        loop {
            let import_desc_file_offset =
                match rva_to_file_offset(payload, import_desc_rva, nt_headers, nt_headers_offset) {
                    Some(offset) => offset,
                    None => break,
                };

            if import_desc_file_offset + mem::size_of::<ImageImportDescriptor>() > payload.len() {
                break;
            }

            let import_desc = ptr::read(
                payload.as_ptr().add(import_desc_file_offset) as *const ImageImportDescriptor
            );

            if import_desc.name == 0 {
                break;
            }

            let dll_name_file_offset = match rva_to_file_offset(
                payload,
                import_desc.name,
                nt_headers,
                nt_headers_offset,
            ) {
                Some(offset) => offset,
                None => {
                    import_desc_rva += mem::size_of::<ImageImportDescriptor>() as u32;
                    continue;
                }
            };

            let dll_name_ptr = payload.as_ptr().add(dll_name_file_offset);
            let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr as *const i8)
                .to_string_lossy()
                .into_owned();

            let dll_handle = LoadLibraryA(dll_name_ptr);
            if dll_handle == 0 {
                return Err(InjectionError::ImportResolutionFailed(format!(
                    "Failed to load DLL '{}': {:?}",
                    dll_name,
                    GetLastError()
                )));
            }

            let mut thunk_rva = if import_desc.original_first_thunk != 0 {
                import_desc.original_first_thunk
            } else {
                import_desc.first_thunk
            };
            let mut iat_rva = import_desc.first_thunk;

            loop {
                let thunk_file_offset =
                    match rva_to_file_offset(payload, thunk_rva, nt_headers, nt_headers_offset) {
                        Some(offset) => offset,
                        None => break,
                    };

                if thunk_file_offset + 8 > payload.len() {
                    break;
                }

                let thunk_data = ptr::read(payload.as_ptr().add(thunk_file_offset) as *const u64);

                if thunk_data == 0 {
                    break;
                }

                let func_addr: *const std::ffi::c_void;
                let func_name: String;

                if thunk_data & 0x8000000000000000 != 0 {
                    let ordinal = (thunk_data & 0xFFFF) as u16;
                    func_addr = GetProcAddress(dll_handle, ordinal as usize as *const u8);
                    func_name = format!("ordinal {}", ordinal);
                } else {
                    let name_rva = (thunk_data & 0x7FFFFFFF) as u32;
                    let name_file_offset = match rva_to_file_offset(
                        payload,
                        name_rva,
                        nt_headers,
                        nt_headers_offset,
                    ) {
                        Some(offset) => offset,
                        None => {
                            thunk_rva += 8;
                            iat_rva += 8;
                            continue;
                        }
                    };

                    let func_name_ptr = payload.as_ptr().add(name_file_offset + 2);
                    func_name = std::ffi::CStr::from_ptr(func_name_ptr as *const i8)
                        .to_string_lossy()
                        .into_owned();
                    func_addr = GetProcAddress(dll_handle, func_name_ptr);
                }

                if func_addr.is_null() {
                    return Err(InjectionError::ImportResolutionFailed(format!(
                        "Failed to resolve '{}' from '{}'",
                        func_name, dll_name
                    )));
                }

                let iat_entry_addr = new_image_base as usize + iat_rva as usize;
                let func_addr_value = func_addr as u64;

                write_process_memory_checked(
                    info.process.hProcess,
                    iat_entry_addr as *mut std::ffi::c_void,
                    &func_addr_value as *const _ as *const std::ffi::c_void,
                    8,
                    &format!("Writing IAT entry for '{}'", func_name),
                )?;

                thunk_rva += 8;
                iat_rva += 8;
            }

            import_desc_rva += mem::size_of::<ImageImportDescriptor>() as u32;
        }

        Ok(())
    }
}
