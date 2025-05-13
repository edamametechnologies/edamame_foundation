#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};

// Simple key and value types - no complex operations
#[repr(C)]
struct Key {
    padding: [u8; 16],  // Simple padding to ensure alignment
}

#[repr(C)]
struct Value {
    pid: u32,
}

#[map(name = "l7_connections")]
static mut L7_CONNECTIONS: HashMap<Key, Value> =
    HashMap::<Key, Value>::with_max_entries(16, 0);

// Simplest possible kprobe implementation
#[kprobe(function = "inet_sock_set_state")]
pub fn minimal_probe(ctx: ProbeContext) -> u32 {
    // Just return 0 - don't even try to access maps or helpers
    // This is just to verify we can load the simplest possible kprobe
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_begin_unwind() -> i64 {
    // Stub panic handler for BPF — should never be called at runtime
    0
}