package tls

// NSS QUIC key derivation function offset discovery.
//
// Firefox's QUIC engine (neqo) derives encryption keys via NSS's internal
// tls13_HkdfExpandLabelRaw function in libssl3.so. This function is NOT
// exported in the dynamic symbol table — it's internal to NSS.
//
// Discovery approach:
//   1. Find the PLT entry for PK11_Derive (called by tls13_HkdfExpandLabelRaw)
//   2. Find all BL/call instructions targeting PK11_Derive in .text
//   3. Walk backward from each call site to find the function prologue
//   4. Verify candidate by checking instruction patterns near the prologue
//   5. Return file offset of the matching function

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
)

// findNSSQUICHkdfOffset analyzes an NSS libssl3.so binary and returns the file
// offset of tls13_HkdfExpandLabelRaw — the internal function that writes raw
// QUIC key material into a caller-provided buffer.
//
// Returns (offset, nil) on success.
func findNSSQUICHkdfOffset(path string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	// Step 1: Find the PLT entry for PK11_Derive.
	pk11DeriveAddr, err := findPLTEntry(f, "PK11_Derive")
	if err != nil {
		return 0, fmt.Errorf("find PK11_Derive PLT: %w", err)
	}

	textSection := f.Section(".text")
	if textSection == nil {
		return 0, fmt.Errorf("no .text section")
	}
	textData, err := textSection.Data()
	if err != nil {
		return 0, fmt.Errorf("read .text: %w", err)
	}
	textBase := textSection.Addr

	// Step 2: Find all BL instructions targeting PK11_Derive.
	callSites := findAllBLCallSites(textData, textBase, pk11DeriveAddr)
	if len(callSites) == 0 {
		return 0, fmt.Errorf("no BL instructions targeting PK11_Derive found")
	}

	// Step 3: For each call site, walk backward to find the function prologue
	// and validate it looks like tls13_HkdfExpandLabelRaw.
	for _, csOff := range callSites {
		funcStart := findFunctionPrologue(textData, csOff)
		if funcStart < 0 {
			continue
		}

		// Step 4: Validate — tls13_HkdfExpandLabelRaw has 9 parameters which
		// means it saves many registers in the prologue (STP for x19-x28+x29+x30).
		// It also has characteristic HKDF label handling (comparison with string constants).
		if isLikelyHkdfExpandLabel(textData, funcStart, csOff) {
			funcVA := textBase + uint64(funcStart)
			fileOff := nssVAToFileOffset(f, funcVA)
			if fileOff == 0 {
				continue
			}
			log.Printf("[tls] NSS QUIC HKDF offset: tls13_HkdfExpandLabelRaw=0x%x (%s)", fileOff, path)
			return fileOff, nil
		}
	}

	return 0, fmt.Errorf("tls13_HkdfExpandLabelRaw not found among %d PK11_Derive callers", len(callSites))
}

// findAllBLCallSites returns all offsets within textData where a BL instruction
// targets the given address. ARM64-specific.
func findAllBLCallSites(textData []byte, textBase, targetAddr uint64) []int {
	var sites []int
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
			sites = append(sites, off)
		}
	}
	return sites
}

// findFunctionPrologue walks backward from callSiteOff to find the most recent
// function prologue. On ARM64, function prologues typically start with:
//   STP x29, x30, [sp, #-N]!   (save frame pointer + link register)
// or similar register-saving STP instructions.
//
// Returns the offset within textData of the prologue, or -1 if not found.
func findFunctionPrologue(textData []byte, callSiteOff int) int {
	// Search backward up to 2048 instructions (8KB) for the prologue.
	maxSearch := 2048 * 4
	startOff := callSiteOff - maxSearch
	if startOff < 0 {
		startOff = 0
	}

	// Walk backward looking for STP x29, x30, [sp, #-N]! (pre-index).
	// Encoding: 10 101 0 011 0 imm7 11110 11111 11101
	// = 0xA9 [imm7+0] 0x7B 0xFD in little-endian (varies with imm7)
	// Mask: 0xFFC003FF == 0xA98003FD for STP x29, x30, [sp, #-N]!
	bestCandidate := -1
	for off := callSiteOff - 4; off >= startOff; off -= 4 {
		insn := binary.LittleEndian.Uint32(textData[off:])
		// STP x29, x30, [sp, #imm]! (pre-indexed)
		// op=10, V=0, opc=101, L=0, pre-index: 11
		// Encoding: 1010100 110 imm7 Rt2(11110) Rn(11111) Rt1(11101)
		if insn&0xFFE003FF == 0xA98003FD {
			bestCandidate = off
			break
		}
		// Alternative: SUB sp, sp, #imm (stack allocation at function start)
		// Encoding: 1101000100 imm12 11111 11111
		if insn&0xFF0003FF == 0xD10003FF {
			// Check if followed by STP within next few instructions
			for j := off + 4; j < off+20 && j+4 <= len(textData); j += 4 {
				next := binary.LittleEndian.Uint32(textData[j:])
				if next&0xFFC003FF == 0xA90003FD { // STP x29, x30, [sp, #imm] (signed offset)
					bestCandidate = off
					break
				}
			}
			if bestCandidate >= 0 {
				break
			}
		}
	}

	return bestCandidate
}

// isLikelyHkdfExpandLabel performs heuristic validation that the function
// starting at funcStart is tls13_HkdfExpandLabelRaw. Checks:
//   - Large frame (many saved registers — 9 params means lots of spills)
//   - Has BL to PK11_Derive (already known from the call site)
//   - Function body is substantial (>= 80 instructions before the PK11_Derive call)
//   - Has multiple ADR/ADRP instructions (string constant references for label handling)
func isLikelyHkdfExpandLabel(textData []byte, funcStart, callSiteOff int) bool {
	if funcStart < 0 || callSiteOff <= funcStart {
		return false
	}

	instrsBefore := (callSiteOff - funcStart) / 4
	// tls13_HkdfExpandLabelRaw is a substantial function (~100-200 instructions).
	// Smaller functions that call PK11_Derive are likely other derivation helpers.
	if instrsBefore < 40 {
		return false
	}

	// Count ADR/ADRP instructions in the function body (up to callSite + 100).
	// HKDF expand label has several string references for label construction.
	adrCount := 0
	endOff := callSiteOff + 400
	if endOff > len(textData) {
		endOff = len(textData)
	}
	for off := funcStart; off+4 <= endOff; off += 4 {
		insn := binary.LittleEndian.Uint32(textData[off:])
		// ADR: 0 immlo(2) 10000 immhi(19) Rd(5) → masked with 0x9F000000 == 0x10000000
		// ADRP: 1 immlo(2) 10000 immhi(19) Rd(5) → masked with 0x9F000000 == 0x90000000
		if insn&0x9F000000 == 0x10000000 || insn&0x9F000000 == 0x90000000 {
			adrCount++
		}
	}
	// HKDF function needs to reference label strings, CKM constants, etc.
	if adrCount < 3 {
		return false
	}

	// Count STP instructions in the prologue area (first 20 instructions).
	// A 9-parameter function saves many callee-saved registers.
	stpCount := 0
	prologueEnd := funcStart + 80
	if prologueEnd > len(textData) {
		prologueEnd = len(textData)
	}
	for off := funcStart; off+4 <= prologueEnd; off += 4 {
		insn := binary.LittleEndian.Uint32(textData[off:])
		// STP (any variant with X registers): top bits 10 1 01 ...
		if insn&0x7E000000 == 0x28000000 || // STP 32-bit
			insn&0x7E000000 == 0x2A000000 { // STP 64-bit
			stpCount++
		}
		// More common encoding: 1x101001xx
		if insn&0xFE000000 == 0xA8000000 || insn&0xFE000000 == 0xA9000000 {
			stpCount++
		}
	}
	// 9 parameters → needs to save at least a few callee-saved registers.
	if stpCount < 2 {
		return false
	}

	return true
}
