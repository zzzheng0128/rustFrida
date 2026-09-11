//! Host-only runner for the existing instruction arithmetic tests.
//! Compile directly with rustc through scripts/test_offline_a64.py.
//! This does not load the Android agent or execute generated instructions.

#![allow(dead_code)]

#[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
compile_error!("offline A64 tests require a 64-bit little-endian host");

#[path = "../src/arm64_relocator.rs"]
mod arm64_relocator;

mod trace {
    // Input fixture only: this runner does not validate the production ABI.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct UserRegs {
        pub regs: [usize; 31],
        pub sp: usize,
        pub pc: usize,
        pub pstate: usize,
    }

    mod transformer {
        pub fn mtransform_addr() -> usize {
            // Numeric fixture; no code is mapped or called at this address.
            0x1234_5678_9abc_0000
        }
    }

    mod arm64_analysis {
        include!("../src/trace/arm64_analysis.rs");
    }

    mod arm64_codegen {
        include!("../src/trace/arm64_codegen.rs");
    }
}
