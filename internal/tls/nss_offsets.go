package tls

// NSS internal function offset discovery.
//
// Firefox's libssl3.so contains NSS-internal plaintext I/O functions in the
// NSPR PRIOMethods virtual table.  These are NOT exported in the dynamic
// symbol table because they're static/internal to NSS.
//
// Through binary analysis of Firefox's libssl3.so on ARM64, we discover the
// function at the send slot (struct offset 144) in the ssl_methods table.
// Empirically, this function carries plaintext that has been decrypted by
// NSS — when hooked with entry+return probes, the buffer contains incoming
// plaintext (HTTP responses) at return time.  We use this as our read hook.
//
// For outgoing plaintext (HTTP requests), Firefox uses PR_Write on
// libnspr4.so, which carries plaintext at entry time.  The agent hooks
// PR_Write separately via the standard libnspr4.so attachment path.
//
// Discovery algorithm:
//
//  1. Find the PLT stub for PR_GetDefaultIOMethods (called during init)
//  2. Find the call site in .text that calls it, followed by memcpy
//  3. After the memcpy, the init function overwrites specific method table
//     slots using ADR + STP instructions.  The STP at struct offset 136
//     stores two consecutive function pointers:
//
//       adr Xa, <func_at_136>
//       adr Xb, <func_at_144>        ; ← plaintext recv function
//       stp Xa, Xb, [base, #136]     ; [136]=func_a, [144]=func_b
//
// The function stored at offset 144 has the NSPR send/recv signature:
//   PRInt32 fn(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags, PRIntervalTimeout timeout)
// with buf at x1 and amount at x2.

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
)

// findNSSReadOffset analyzes an NSS libssl3.so binary and returns the file
// offset of the internal function at PRIOMethods send slot (struct offset 144).
// Empirically, this function carries incoming plaintext at return time and is
// suitable for hooking with entry+return read probes.
//
// Returns (readOff, nil) on success.  writeOff is not provided because
// outgoing plaintext is captured via PR_Write on libnspr4.so instead.
func findNSSReadOffset(path string) (readOff uint64, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	// Step 1: Find the PLT entry for PR_GetDefaultIOMethods.
	pltAddr, err := findPLTEntry(f, "PR_GetDefaultIOMethods")
	if err != nil {
		return 0, fmt.Errorf("find PLT entry: %w", err)
	}

	// Step 2: Read .text section and find the BL instruction that calls pltAddr.
	textSection := f.Section(".text")
	if textSection == nil {
		return 0, fmt.Errorf("no .text section")
	}
	textData, err := textSection.Data()
	if err != nil {
		return 0, fmt.Errorf("read .text: %w", err)
	}
	textBase := textSection.Addr

	callSiteOff := findBLCallSite(textData, textBase, pltAddr)
	if callSiteOff < 0 {
		return 0, fmt.Errorf("PR_GetDefaultIOMethods call site not found")
	}

	// Step 3: Scan forward for the STP at struct offset 136, extract the
	// function at slot 144 (rt2).
	readVA := extractRecvFunctionVA(textData, textBase, callSiteOff)
	if readVA == 0 {
		return 0, fmt.Errorf("could not extract NSS recv function from init")
	}

	// Convert virtual address to file offset.
	readOff = nssVAToFileOffset(f, readVA)
	if readOff == 0 {
		return 0, fmt.Errorf("VA→file offset conversion failed (va=0x%x)", readVA)
	}

	log.Printf("[tls] NSS libssl3.so offset: nss_recv_func=0x%x (%s)", readOff, path)
	return readOff, nil
}

// findPLTEntry returns the virtual address of the PLT stub for the given symbol.
func findPLTEntry(f *elf.File, symName string) (uint64, error) {
	dynsyms, err := f.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("read .dynsym: %w", err)
	}
	symIdx := -1
	for i, s := range dynsyms {
		if s.Name == symName {
			symIdx = i + 1 // index 0 is the undefined symbol
			break
		}
	}
	if symIdx < 0 {
		return 0, fmt.Errorf("symbol %q not in .dynsym", symName)
	}

	relaPlt := f.Section(".rela.plt")
	if relaPlt == nil {
		return 0, fmt.Errorf("no .rela.plt section")
	}
	relaData, err := relaPlt.Data()
	if err != nil {
		return 0, fmt.Errorf("read .rela.plt: %w", err)
	}

	// Each Rela64 entry is 24 bytes: offset(8) + info(8) + addend(8).
	var gotAddr uint64
	for i := 0; i+24 <= len(relaData); i += 24 {
		relOff := binary.LittleEndian.Uint64(relaData[i:])
		relInfo := binary.LittleEndian.Uint64(relaData[i+8:])
		if int(relInfo>>32) == symIdx {
			gotAddr = relOff
			break
		}
	}
	if gotAddr == 0 {
		return 0, fmt.Errorf("no JUMP_SLOT for %q", symName)
	}

	// Scan .plt for the stub that loads from this GOT address.
	pltSection := f.Section(".plt")
	if pltSection == nil {
		return 0, fmt.Errorf("no .plt section")
	}
	pltData, err := pltSection.Data()
	if err != nil {
		return 0, fmt.Errorf("read .plt: %w", err)
	}
	pltBase := pltSection.Addr

	// Each AARCH64 PLT entry is 16 bytes: adrp x16 / ldr x17 / add x16 / br x17.
	for off := 32; off+16 <= len(pltData); off += 16 {
		addr := pltBase + uint64(off)
		if decodePLTTarget(pltData[off:off+16], addr) == gotAddr {
			return addr, nil
		}
	}
	return 0, fmt.Errorf("PLT stub for %q not found", symName)
}

// decodePLTTarget decodes an AARCH64 PLT entry and returns the GOT address it loads from.
func decodePLTTarget(data []byte, pc uint64) uint64 {
	if len(data) < 8 {
		return 0
	}
	insn0 := binary.LittleEndian.Uint32(data[0:4])
	if insn0&0x9F00001F != 0x90000010 { // ADRP x16
		return 0
	}
	immhi := (insn0 >> 5) & 0x7FFFF
	immlo := (insn0 >> 29) & 0x3
	imm := int64((immhi<<2)|immlo) << 12
	if immhi&0x40000 != 0 {
		imm |= ^int64(0) << 33
	}
	page := (pc &^ 0xFFF) + uint64(imm)

	insn1 := binary.LittleEndian.Uint32(data[4:8])
	if insn1&0xFFC003FF != 0xF9400211 { // LDR x17, [x16, #imm]
		return 0
	}
	ldrOff := ((insn1 >> 10) & 0xFFF) << 3
	return page + uint64(ldrOff)
}

// findBLCallSite scans for a BL instruction targeting targetAddr.
func findBLCallSite(textData []byte, textBase, targetAddr uint64) int {
	for off := 0; off+4 <= len(textData); off += 4 {
		insn := binary.LittleEndian.Uint32(textData[off:])
		if insn&0xFC000000 != 0x94000000 { // BL
			continue
		}
		imm26 := insn & 0x03FFFFFF
		offset := int64(imm26) << 2
		if imm26&0x02000000 != 0 {
			offset |= ^int64(0) << 28
		}
		if uint64(int64(textBase+uint64(off))+offset) == targetAddr {
			return off
		}
	}
	return -1
}

// extractRecvFunctionVA scans forward from the call site to find the STP
// instruction at struct offset 128, which stores the functions for the
// shutdown and recv slots:
//   - rt1 → [base+128] (PRIOMethods.shutdown slot)
//   - rt2 → [base+136] (PRIOMethods.recv slot) ← what we want
//
// The recv function (ssl_DefRecv) carries incoming plaintext — the buffer
// is filled with decrypted data during execution and is readable at return.
//
// We also extract the send function from STP at offset 136:
//   - rt2 → [base+144] (PRIOMethods.send slot)
// but this is in the WRITE path and is captured via PR_Write instead.
func extractRecvFunctionVA(textData []byte, textBase uint64, callSiteOff int) uint64 {
	adrVals := make(map[uint32]uint64) // register → VA loaded by ADR

	maxScan := callSiteOff + 200*4
	if maxScan > len(textData) {
		maxScan = len(textData)
	}

	for off := callSiteOff; off+4 <= maxScan; off += 4 {
		insn := binary.LittleEndian.Uint32(textData[off:])
		pc := textBase + uint64(off)

		// ADR Xd, <label>: op=0, immlo(2), 10000, immhi(19), Rd(5)
		if insn&0x9F000000 == 0x10000000 {
			rd := insn & 0x1F
			immhi := (insn >> 5) & 0x7FFFF
			immlo := (insn >> 29) & 0x3
			imm := int64((immhi << 2) | immlo)
			if immhi&0x40000 != 0 {
				imm |= ^int64(0) << 21
			}
			adrVals[rd] = uint64(int64(pc) + imm)
			continue
		}

		// STP Xt1, Xt2, [Xn, #imm] (signed offset, 64-bit)
		// Encoding: 10 101 0 010 0 imm7 Rt2 Rn Rt1
		if insn&0xFFC00000 == 0xA9000000 {
			rt1 := insn & 0x1F
			rt2 := (insn >> 10) & 0x1F
			imm7 := (insn >> 15) & 0x7F
			offset := int64(imm7) << 3
			if imm7&0x40 != 0 {
				offset |= ^int64(0) << 10
			}

			switch offset {
			case 128:
				// STP at offset 128: rt1→[128]=shutdown, rt2→[136]=recv
				if v, ok := adrVals[rt2]; ok {
					return v
				}
			case 136:
				// STP at offset 136: rt1→[136]=recv, rt2→[144]=send
				// Use rt1 for recv.
				if v, ok := adrVals[rt1]; ok {
					return v
				}
			}
		}
	}
	return 0
}

// nssVAToFileOffset converts a virtual address to a file offset.
func nssVAToFileOffset(f *elf.File, va uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if prog.Vaddr <= va && va < prog.Vaddr+prog.Memsz {
			return va - prog.Vaddr + prog.Off
		}
	}
	return 0
}
