//! Host-only runner for the existing instruction arithmetic tests.
//! Compile directly with rustc through scripts/test_offline_a64.py.
//! This does not load the Android agent or execute generated instructions.

#![allow(dead_code)]

#[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
compile_error!("offline A64 tests require a 64-bit little-endian host");

// The production modules keep logging lightweight on the target.  The host
// arithmetic runner supplies a no-op sink so it can validate instruction
// decoding and relocation without linking the Android socket layer.
mod communication {
    pub fn write_stream(_: &[u8]) {}
}

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

    #[cfg(test)]
    mod tests {
        use super::arm64_analysis::{is_arm64_branch, is_arm64_call, resolve_next_addr};
        use super::UserRegs;
        use crate::arm64_relocator::{relocate_one_a64, RelocStatus};

        #[test]
        fn decodes_native_little_endian_a64_words() {
            assert!(is_arm64_branch(0x1400_0000)); // B
            assert!(is_arm64_branch(0x9400_0000)); // BL
            assert!(is_arm64_branch(0xd65f_03c0)); // RET
            assert!(!is_arm64_branch(0xd503_201f)); // NOP
            assert!(is_arm64_call(0x9400_0000));
            assert!(is_arm64_call(0xd63f_0000)); // BLR X0
        }

        #[test]
        fn resolves_direct_and_conditional_targets_from_branch_pc() {
            let direct = [0x1400_0400u32]; // B +0x1000
            let direct_pc = direct.as_ptr() as usize;
            assert_eq!(
                unsafe { resolve_next_addr(direct.as_ptr(), UserRegs::default()) },
                Some(direct_pc + 0x1000)
            );

            let conditional = [0x5400_0040u32]; // B.EQ +8
            let conditional_pc = conditional.as_ptr() as usize;
            let mut taken = UserRegs::default();
            taken.pstate = 1 << 30; // Z=1
            assert_eq!(
                unsafe { resolve_next_addr(conditional.as_ptr(), taken) },
                Some(conditional_pc + 8)
            );
            assert_eq!(
                unsafe { resolve_next_addr(conditional.as_ptr(), UserRegs::default()) },
                Some(conditional_pc + 4)
            );
        }

        #[test]
        fn relocates_native_little_endian_branch_without_byte_swapping() {
            let source = [0x1400_0400u32]; // source +0x1000
            let mut destination = [0u32; 1];
            let src = source.as_ptr() as usize;
            let dst = destination.as_mut_ptr() as usize;
            assert_eq!(unsafe { relocate_one_a64(src, dst) }, RelocStatus::Patched);
            let target = src + 0x1000;
            let new_imm = (((target as isize - dst as isize) >> 2) as u32) & 0x03ff_ffff;
            assert_eq!(destination[0], 0x1400_0000 | new_imm);
        }
    }
}
