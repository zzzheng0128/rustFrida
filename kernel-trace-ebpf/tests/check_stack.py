#!/usr/bin/env python3
"""Offline stack/call-chain estimate for an ELF64 little-endian eBPF object.

Usage: python3 kernel-trace-ebpf/tests/check_stack.py PATH_TO_BPF_OBJECT
       python3 kernel-trace-ebpf/tests/check_stack.py --self-test

Uses only Python's standard library; never loads or attaches a BPF program.
Every executable entry section is checked, including reachable .text functions.
Frames cost round_up(max(frame_bytes, 1), 32), matching Linux's stack check.

The estimate includes fixed stack references and derived stack pointers within
each function, including control-flow joins. Unsupported dynamic stack offsets
or spilled stack pointers make the result INCONCLUSIVE. Caller stack pointers
passed to or returned by subprograms are not tracked across the call boundary;
therefore this tool cannot prove a general stack upper bound. It also does not
reproduce verifier path pruning or validate types, initialization, reference
lifetimes, helper contracts, or instruction complexity. An estimate within the
limit is not equivalent to acceptance by the kernel verifier.
"""

import argparse
from collections import deque
from dataclasses import dataclass
from pathlib import Path
import struct
import sys
import unittest


@dataclass(frozen=True)
class Instruction:
    code: int
    dst: int = 0
    src: int = 0
    offset: int = 0
    immediate: int = 0


@dataclass
class Function:
    name: str
    section: str
    address: int
    instructions: list
    calls: dict


def read_elf(path):
    data = Path(path).read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected an ELF64 little-endian object")
    if struct.unpack_from("<H", data, 18)[0] != 247:
        raise ValueError("ELF machine is not EM_BPF")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count, names_index = struct.unpack_from("<HHH", data, 58)
    if section_size != 64 or not section_count or names_index >= section_count:
        raise ValueError("unsupported ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, section_offset + i * 64)
                for i in range(section_count)]

    def contents(section):
        start, size = section[4:6]
        if start + size > len(data):
            raise ValueError("section extends past EOF")
        return data[start:start + size]

    def string(table, index):
        return table[index:table.index(b"\0", index)].decode("utf-8", "replace")

    section_names = contents(sections[names_index])
    names = [string(section_names, section[0]) for section in sections]
    symbols = {}
    functions = {}
    for section_index, section in enumerate(sections):
        if section[1] != 2:  # SHT_SYMTAB
            continue
        if section[9] != 24:
            raise ValueError("unsupported ELF symbol size")
        strings = contents(sections[section[6]])
        table = []
        for offset in range(0, section[5], 24):
            name, info, _, index, value, size = struct.unpack_from("<IBBHQQ", contents(section), offset)
            symbol = (string(strings, name), info & 15, index, value, size)
            table.append(symbol)
            if symbol[1] != 2 or not size or index >= len(sections):
                continue
            if not sections[index][2] & 4:  # SHF_EXECINSTR
                continue
            if value % 8 or size % 8:
                raise ValueError("unaligned BPF function")
            raw = contents(sections[index])[value:value + size]
            if len(raw) != size:
                raise ValueError("function extends past section")
            instructions = []
            for instruction_offset in range(0, size, 8):
                opcode, registers, displacement, immediate = struct.unpack_from("<BBhi", raw, instruction_offset)
                instructions.append(Instruction(opcode, registers & 15, registers >> 4, displacement, immediate))
            functions[(index, value)] = Function(symbol[0], names[index], value, instructions, {})
        symbols[section_index] = table

    relocations = {}
    for section in sections:
        if section[1] not in (4, 9):  # SHT_RELA / SHT_REL
            continue
        stride = 24 if section[1] == 4 else 16
        for offset in range(0, section[5], stride):
            location, info = struct.unpack_from("<QQ", contents(section), offset)
            if info & 0xffffffff != 10:  # R_BPF_64_32, a BPF-to-BPF call
                continue
            symbol = symbols[section[6]][info >> 32]
            relocations[(section[7], location)] = symbol

    for key, function in functions.items():
        for index, instruction in enumerate(function.instructions):
            if instruction.code != 0x85 or instruction.src != 1:
                continue
            symbol = relocations.get((key[0], function.address + index * 8))
            if symbol is not None and symbol[1] == 2:
                target = (symbol[2], symbol[3])
            elif symbol is not None and symbol[1] == 3:  # section symbol
                target = (symbol[2], (instruction.immediate + 1) * 8)
            else:
                target = (key[0], function.address + (index + instruction.immediate + 1) * 8)
            if target not in functions:
                raise ValueError(f"unresolved call in {function.name} at instruction {index}")
            function.calls[index] = target
    if not functions:
        raise ValueError("no executable BPF function symbols")
    return functions


# Value: U=unknown non-frame value, C=constant, S=possible pointer into this frame.
UNKNOWN = ("U", 0, 0)


def frame_bound(function):
    warnings = set()
    depth = 0
    states = {}
    initial = [UNKNOWN] * 11
    initial[10] = ("S", 0, 0)
    states[0] = tuple(initial)
    pending = deque([0])
    changes = 0

    def merge(a, b):
        if a == b:
            return a
        if a[0] == "S" or b[0] == "S":
            if a[0] != "S" or b[0] != "S":
                warnings.add("stack/non-stack register merge")
                return a if a[0] == "S" else b
            low, high = min(a[1], b[1]), max(a[2], b[2])
            if low < -8192 or high > 8192:
                warnings.add("unbounded derived stack pointer")
                low, high = -8192, 8192
            return ("S", low, high)
        return UNKNOWN

    while pending:
        index = pending.popleft()
        if not 0 <= index < len(function.instructions):
            raise ValueError(f"branch outside {function.name}")
        registers = list(states[index])
        instruction = function.instructions[index]
        code, dst, src = instruction.code, instruction.dst, instruction.src
        kind, operation = code & 7, code & 0xf0
        following = [index + 1]
        if code == 0x18:  # LD_IMM64, relocation may denote an external/map pointer
            if index + 1 >= len(function.instructions):
                raise ValueError("truncated LD_IMM64")
            registers[dst] = UNKNOWN
            following = [index + 2]
        elif kind in (1, 2, 3):  # load/store memory; include atomics
            base = registers[src if kind == 1 else dst]
            if base[0] == "S":
                depth = max(depth, -(base[1] + instruction.offset))
            if kind == 1:
                registers[dst] = UNKNOWN
            elif kind == 3 and registers[src][0] == "S":
                warnings.add("spilled stack pointer (reload tracking unsupported)")
        elif kind in (4, 7):  # ALU32 / ALU64
            left = registers[dst]
            right = registers[src] if code & 8 else ("C", instruction.immediate, instruction.immediate)
            if operation == 0xb0:  # MOV
                registers[dst] = right if kind == 7 else UNKNOWN
            elif operation in (0, 0x10):  # ADD / SUB
                sign = 1 if operation == 0 else -1
                if left[0] == "S" and right[0] == "C" and kind == 7:
                    registers[dst] = ("S", left[1] + sign * right[1], left[2] + sign * right[1])
                elif left[0] == "C" and right[0] == "S" and operation == 0 and kind == 7:
                    registers[dst] = ("S", right[1] + left[1], right[2] + left[1])
                elif left[0] == right[0] == "C":
                    value = left[1] + sign * right[1]
                    registers[dst] = ("C", value, value)
                else:
                    if left[0] == "S" or right[0] == "S":
                        warnings.add("dynamic stack-pointer arithmetic")
                    registers[dst] = UNKNOWN
            else:
                if left[0] == "S" or right[0] == "S":
                    warnings.add("unsupported stack-pointer ALU operation")
                registers[dst] = UNKNOWN
        elif kind in (5, 6):  # JMP / JMP32
            if operation == 0x90:
                following = []
            elif operation == 0x80:
                if instruction.src not in (0, 1):
                    warnings.add("unsupported call kind")
                registers[:6] = [UNKNOWN] * 6
            else:
                displacement = instruction.immediate if kind == 6 and operation == 0 else instruction.offset
                target = index + 1 + displacement
                following = [target] if operation == 0 else [index + 1, target]
        else:
            warnings.add(f"unsupported instruction 0x{code:02x}")
        for value in registers:
            if value[0] == "S":
                depth = max(depth, -value[1])
        for target in following:
            if target == len(function.instructions):
                raise ValueError(f"fallthrough past {function.name}")
            new = tuple(registers)
            if target in states:
                new = tuple(merge(a, b) for a, b in zip(states[target], new))
            if states.get(target) != new:
                states[target] = new
                pending.append(target)
                changes += 1
                if changes > 100000:
                    raise ValueError(f"dataflow did not converge in {function.name}")
    return depth, sorted(warnings)


def rounded(depth):
    return (max(depth, 1) + 31) // 32 * 32


def worst_chain(functions, bounds, key, ancestors=()):
    if key in ancestors:
        raise ValueError("recursive BPF call graph")
    own = rounded(bounds[key][0])
    candidates = [worst_chain(functions, bounds, target, ancestors + (key,))
                  for target in set(functions[key].calls.values())]
    child_cost, child_path = max(candidates, default=(0, []), key=lambda item: item[0])
    return own + child_cost, [key] + child_path


class Samples(unittest.TestCase):
    def test_zero_byte_callee_still_costs_one_32_byte_frame(self):
        functions = {0: Function("entry", "raw_tp/test", 0, [], {0: 1}),
                     1: Function("memset", ".text", 0, [], {})}
        self.assertEqual(worst_chain(functions, {0: (488, []), 1: (0, [])}, 0), (544, [0, 1]))
        self.assertEqual(worst_chain(functions, {0: (472, []), 1: (0, [])}, 0)[0], 512)

    def test_derived_pointer_and_negative_memory_displacement(self):
        function = Function("sample", "test", 0, [
            Instruction(0xbf, 1, 10), Instruction(0x07, 1, immediate=-64),
            Instruction(0x7a, 1, offset=-8), Instruction(0x95)], {})
        self.assertEqual(frame_bound(function), (72, []))

    def test_dynamic_stack_offset_is_inconclusive(self):
        function = Function("sample", "test", 0, [
            Instruction(0xbf, 1, 10), Instruction(0x0f, 1, 2), Instruction(0x95)], {})
        self.assertIn("dynamic stack-pointer arithmetic", frame_bound(function)[1])

    def test_call_clobbers_arguments_but_keeps_callee_saved_stack_alias(self):
        function = Function("sample", "test", 0, [
            Instruction(0xbf, 6, 10), Instruction(0x07, 6, immediate=-48),
            Instruction(0x85, immediate=1), Instruction(0x7a, 6, offset=-8), Instruction(0x95)], {})
        self.assertEqual(frame_bound(function), (56, []))

    def test_recursion_is_rejected(self):
        function = Function("recursive", ".text", 0, [], {0: 0})
        with self.assertRaisesRegex(ValueError, "recursive"):
            worst_chain({0: function}, {0: (0, [])}, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("object", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        return 0 if unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Samples)).wasSuccessful() else 1
    if not arguments.object:
        parser.error("provide a BPF object or --self-test")
    try:
        functions = read_elf(arguments.object)
        bounds = {key: frame_bound(function) for key, function in functions.items()}
        entries = [key for key, function in functions.items() if not function.section.startswith(".text")]
        if not entries:
            raise ValueError("no program entry sections")
        failed, uncertain = False, False
        for key, function in functions.items():
            depth, warnings = bounds[key]
            print(f"frame {function.name}: estimate={depth} rounded={rounded(depth)} section={function.section}")
            for warning in warnings:
                print(f"  INCONCLUSIVE: {warning}")
        for key in entries:
            cost, chain = worst_chain(functions, bounds, key)
            reachable, pending = set(), [key]
            while pending:
                current = pending.pop()
                if current not in reachable:
                    reachable.add(current)
                    pending.extend(functions[current].calls.values())
            warnings = any(bounds[current][1] for current in reachable)
            status = "ESTIMATE OVER LIMIT" if cost > 512 else "INCONCLUSIVE" if warnings else "ESTIMATE WITHIN LIMIT"
            path = " -> ".join(f"{functions[current].name}[{rounded(bounds[current][0])}]" for current in chain)
            print(f"{status}: {functions[key].name}: {cost}/512 bytes: {path}")
            failed |= cost > 512
            uncertain |= warnings
        print("Offline estimate only; kernel verifier acceptance remains a separate check.")
        return 1 if failed else 2 if uncertain else 0
    except (ValueError, IndexError, KeyError, struct.error, OSError) as error:
        print(f"INCONCLUSIVE: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
