// Copyright 2025 The Go Authors. All rights reserved.
// Copyright 2026 SwarmGuard contributors.
// Use of this source code is governed by the BSD-style license in the repository-root LICENSE file.
//
// ARM64 adaptation of x/crypto v0.55.0's saturated-limb update algorithm
// (sum_generic.go and sum_loong64.s). Branches depend only on message length.
// This experimental port has not undergone independent cryptographic review.

//go:build arm64 && gc && !purego

#include "textflag.h"

// updateBlocks consumes a non-empty, whole number of 16-byte blocks.
// The Go wrapper handles empty input and partial final blocks.
// R0=state, R1=input, R2=length; R3:R5=h; R6:R7=r.
// R8:R11=256-bit product; R12:R14=temporary values.
// As in updateGeneric, the incoming h2 is at most 5 and r is clamped.
// Adding the block raises h2 to at most 7, so h2*r0 and h2*r1 fit
// in 64 bits; the full product fits in four 64-bit limbs.
// This leaf has no stack frame, no calls, and does not use reserved registers.
TEXT ·updateBlocks(SB), NOSPLIT, $0-32
	MOVD state+0(FP), R0
	MOVD msg_base+8(FP), R1
	MOVD msg_len+16(FP), R2
	LDP (R0), (R3, R4)
	MOVD 16(R0), R5
	LDP 24(R0), (R6, R7)
loop:
	// h += block + 2^128.
	LDP (R1), (R12, R13)
	ADDS R12, R3, R3
	ADCS R13, R4, R4
	ADC ZR, R5, R5
	ADD $1, R5, R5
	ADD $16, R1, R1

	// Multiply h by the clamped r, retaining all 256 result bits.
	MUL R3, R6, R8
	UMULH R3, R6, R9
	MUL R4, R6, R12
	UMULH R4, R6, R10
	ADDS R12, R9, R9
	ADC ZR, R10, R10
	MUL R5, R6, R12
	ADD R12, R10, R10
	MUL R3, R7, R12
	UMULH R3, R7, R13
	ADDS R12, R9, R9
	ADC ZR, R13, R14
	MUL R5, R7, R11
	MUL R4, R7, R12
	UMULH R4, R7, R13
	ADDS R12, R10, R10
	ADC R13, R11, R11
	ADDS R14, R10, R10
	ADC ZR, R11, R11

	// Partial reduction modulo 2^130-5: add carry*4, then carry.
	AND $3, R10, R5
	AND $-4, R10, R12
	ADDS R12, R8, R3
	ADCS R11, R9, R4
	ADC ZR, R5, R5
	EXTR $2, R10, R11, R12
	LSR $2, R11, R13
	ADDS R12, R3, R3
	ADCS R13, R4, R4
	ADC ZR, R5, R5

	SUBS $16, R2, R2
	BNE loop
	STP (R3, R4), (R0)
	MOVD R5, 16(R0)
	RET
