#ifndef	_DTRACE_JIT_ISA_H
#define	_DTRACE_JIT_ISA_H

/* Stack variable offsets from RBP */
#define VAR_MSTATE		(base_offset-8)
#define VAR_VSTATE		(base_offset-16)
#define VAR_STATE		(base_offset-24)
#define VAR_DSTATE		(base_offset-32)
#define VAR_FLAGS		(base_offset-40)
#define VAR_ILLVAL		(base_offset-48)
#define VAR_CURCPU		(base_offset-56)
#define VAR_THREAD_SIZE		(base_offset-64)
#define VAR_THREAD_VALUE	(base_offset-72)
#define VAR_ID_SIZE		(base_offset-80)
#define VAR_ID_VALUE		(base_offset-88)
#define VAR_STACK_SIZE		88

/* 64-bit regiters */
#define RAX	0
#define RCX	1
#define RDX	2
#define RBX	3
#define RSP	4
#define RBP	5
#define RSI	6
#define RDI	7
#define R8	8
#define R9	9
#define R10	10
#define R11	11
#define R12	12
#define R13	13
#define R14	14
#define R15	15

#define RSIB	4	/* select SIB in ModRM */

/* Alias for registers as function arguments */
#define FNARG1	RDI
#define FNARG2	RSI
#define FNARG3	RDX
#define FNARG4	RCX
#define FNARG5	R8
#define FNARG6	R9

#define JB	0x0
#define JAE	0x1
#define JE	0x2
#define JZ	0x2
#define JNE	0x3
#define JNZ	0x3
#define JBE	0x4
#define JA	0x5
#define JL	0xa
#define JGE	0xb
#define JLE	0xc
#define JG	0xd

/* REX byte */
#define REX_W		0x48
#define REX_R		0x44
#define REX_X		0x42
#define REX_B		0x41

/* REX byte constructor */
#define REX(w, r, x, b) (REX_RAW(w, r, x, b) ? REX_RAW(w, r, x, b) : NA)
#define REX_RAW(w, r, x, b) \
	((w) ? REX_W : 0) \
	| ((r) >= R8 ? REX_R : 0) \
	| ((x) >= R8 ? REX_X : 0) \
	| ((b) >= R8 ? REX_B : 0)

/* Prefixes */
#define PREFIX_OPSIZE	0x66
#define PREFIX_ADDRSIZE	0x67

/* ModRM mod values */
#define MOD_DEREF	0
#define MOD_DISP8	1
#define MOD_DISP32	2
#define MOD_VAL		3

/* ModRM contructor */
#define ModRM(mod, rm, r) ((mod << 6) | ((r & 7) << 3) | (rm & 7))

#define ModForOffset(offset) \
	((offset) == 0 ? MOD_DEREF : (IS8(offset) ? MOD_DISP8 : MOD_DISP32)) \

/* ModRM accessors */
#define ModRM_mod(modrm)	(((modrm) >> 6) & 3)
#define ModRM_r(modrm)		(((modrm) >> 3) & 7)
#define ModRM_rm(modrm)		((modrm) & 7)

/* SIB scale modes */
#define SIB_1	0
#define SIB_2	1
#define SIB_4	2
#define SIB_8	3

/* SIB constructor */
#define SIB(scale, index, base) ((scale << 6) | ((index & 7) << 3) | (base & 7))

#define NA	-129

#define IS8(v)	((int64_t)(v) >= INT8_MIN && (int64_t)(v) <= INT8_MAX)
#define IS16(v)	((int64_t)(v) >= INT16_MIN && (int64_t)(v) <= INT16_MAX)
#define IS32(v)	((int64_t)(v) >= INT32_MIN && (int64_t)(v) <= INT32_MAX)

/* emit a /r instruction */
#define SlashR(prefix, rex, opcode, modrm, sib, offset, imm, imm_sz) do { \
	const int32_t off = offset; \
	const int64_t im = imm; \
	/* check for a prefix */ \
	if (prefix != NA) \
		emit((int8_t)(prefix)); \
	/* check for a REX byte */ \
	if (rex != NA) \
		emit((int8_t)(rex)); \
	/* always have an opcode */ \
	emit(opcode); \
	if ((modrm) != NA) { \
		emit(modrm); \
		/* check for a SIB */ \
		if (ModRM_rm(modrm) == 4 && ModRM_mod(modrm) != MOD_VAL) \
			emit((int8_t)(sib)); \
		else \
			ASSERT(SIB == NA); \
		/* check for an offset */ \
		if (ModRM_mod(modrm) == MOD_DISP8) { \
			ASSERT(IS8(off)); \
			emit((int8_t)(off)); \
		} else if (ModRM_mod(modrm) == MOD_DISP32) {\
			ASSERT(IS32(off)); \
			emit_data(&off, 4); \
		} else { \
			ASSERT(off == NA); \
		} \
	}  else { \
		/* no ModRM => no SIB or offset */ \
		ASSERT(sib == NA); \
		ASSERT(off == NA); \
	} \
	/* check for an immediate */ \
	emit_imm(im, imm_sz); \
} while (0)

/* emit a +r instruction */
#define PlusR(prefix, rex, opcode, reg, imm, imm_sz) do { \
	/* check for a prefix */ \
	if (prefix != NA) \
		emit((int8_t)(prefix)); \
	/* check for a REX byte */ \
	if (rex != NA) \
		emit((int8_t)(rex)); \
	/* always have an opcode */ \
	emit(opcode | ((reg) & 7)); \
	/* check for an immediate */ \
	emit_imm(imm, imm_sz); \
} while (0)

/* emit an immediate */
#define emit_imm(imm, imm_sz) do { \
	if (imm_sz == 1) { \
		ASSERT(IS8(imm)); \
		emit((int8_t)(imm)); \
	} else if (imm_sz == 2) { \
		ASSERT(IS16(imm)); \
		int16_t w = imm; \
		emit_data(&w, 2); \
	} else if (imm_sz == 4) { \
		ASSERT(IS32(imm)); \
		int32_t d = imm; \
		emit_data(&d, 4); \
	} else if (imm_sz == 8) { \
		int64_t q = imm; \
		emit_data(&q, 8); \
	} else { \
		ASSERT(imm == NA); \
		ASSERT(imm_sz == NA); \
	} \
} while (0)

#define emit_offset(mod, offset) do { \
	if (mod == MOD_DISP8) { \
		emit(offset); \
	} else if (mod == MOD_DISP32) { \
		uint32_t v = offset; \
		emit_data(&v, 4); \
	} \
} while(0)

/* Binary commutative operation */
#define BinCommOp(op) do { \
	if (rd == r1) { \
		if (r2 == 0) { \
			ZERO(RAX); \
			op(RAX, regs[rd]); \
		}  else \
			op(regs[r2], regs[rd]); \
	} else if (rd == r2) { \
		if (r1 == 0) { \
			ZERO(RAX); \
			op(RAX, regs[rd]); \
		} else \
			op(regs[r1], regs[rd]); \
	} else { \
		if (r1 == 0) { \
			ZERO(regs[rd]); \
			op(regs[r2], regs[rd]); \
		} else if (r2 == 0) { \
			ZERO(regs[rd]); \
			op(regs[r1], regs[rd]); \
		} else { \
			MOV(regs[r1], regs[rd]); \
			op(regs[r2], regs[rd]); \
		} \
	} \
} while (0)

#define ShiftOp(op) do { \
	if (r1 == 0) { \
		ZERO(regs[rd]); \
	} else if (r2 == 0) { \
		MOV(regs[r1], regs[rd]); \
	} else if (rd == r1) { \
		op(regs[r2], regs[r1]); \
	} else if (rd == r2) { \
		MOV(regs[r1], RAX); \
		op(regs[r2], RAX); \
		MOV(RAX, regs[rd]); \
	} else { \
		MOV(regs[r1], regs[rd]); \
		op(regs[r2], regs[rd]); \
	} \
} while (0)

/*
 * Pseudo assembly
 */

/* add sr64, dr64 */
#define ADD(sr64, dr64) SlashR(NA, REX(1, dr64, NA, sr64), 0x03, \
    ModRM(MOD_VAL, sr64, dr64), NA, NA, NA, NA)

/* add imm, r64 */
#define ADDi(imm, r64) do { \
	if (imm == 0) \
		break; \
	bool is8 = IS8(imm); \
	SlashR(NA, REX(1, NA, NA, r64), (is8 ? 0x83 : 0x81), \
	    ModRM(MOD_VAL, r64, 0), NA, NA, imm, (is8 ? 1 : 4)); \
} while (0)

/* and sr64, dr64 */
#define AND(sr64, dr64) SlashR(NA, REX(1, dr64, NA, sr64), 0x23, \
    ModRM(MOD_VAL, sr64, dr64), NA, NA, NA, NA)

/* call *r64 */
#define CALL(ptr) do { \
	ASSERT(ptr != NULL); \
	SET((uintptr_t)ptr, RAX); \
	SlashR(NA, NA, 0xff, ModRM(MOD_VAL, RAX, 2), NA, NA, NA, NA); \
} while (0)

/* Save registers to stack before call */
#define CALL_SAVE() do { \
	if (analysis.used_regs & (1 << 7)) \
		PUSH(R10); \
	if (analysis.used_regs & (1 << 6)) \
		PUSH(R11); \
} while (0)

/* Restore registers from stack after call */
#define CALL_RESTORE() do { \
	if (analysis.used_regs & (1 << 6)) \
		POP(R11); \
	if (analysis.used_regs & (1 << 7)) \
		POP(R10); \
} while (0)

/* cmp ar64, br64 */
#define CMP(ar64, br64) SlashR(NA, REX(1, ar64, NA, br64), 0x3b, \
	    ModRM(MOD_VAL, br64, ar64), NA, NA, NA, NA);

/* cmp r64, imm */
#define CMPi(r64, imm) do { \
	bool is8 = IS8(imm); \
	SlashR(NA, REX(1, NA, NA, r64), (is8 ? 0x83 : 0x81), \
	    ModRM(MOD_VAL, r64, 7), NA, NA, imm, (is8 ? 1 : 4)); \
} while (0)

/* cmp [base] + offset, imm */
#define CMPmi8(base, offset, imm) SlashR(NA, REX(0, NA, NA, base), 0x80, \
	    ModRM(ModForOffset(offset), base, 7), NA, offset, imm, 1) \

/* div r64 */
#define DIV(r64) do { \
	/* Zero extend RAX to RDX:RAX */ \
	ZERO(RDX); \
	/* idiv */ \
	SlashR(NA, REX(1, NA, NA, r64), 0xf7, ModRM(MOD_VAL, r64, 6), NA, NA, \
	     NA, NA); \
} while (0)

/* get variable and load into r64 */
/* TODO(andrew): how about tracking where the variable is i.e. in a register or
 * memory for a bit of optimisation? */
#define GET(var, r64) LOAD(RBP, var, r64)

/* idiv r64 */
#define IDIV(r64) do { \
	/* cqto to sign extend RAX to RDX:RAX */ \
	SlashR(NA, REX_W, 0x99, NA, NA, NA, NA, NA); \
	/* idiv */ \
	SlashR(NA, REX(1, NA, NA, r64), 0xf7, ModRM(MOD_VAL, r64, 7), NA, NA, \
	     NA, NA); \
} while (0)

/* imul sr64, dr64 */
#define IMUL(sr64, dr64) do { \
	uint8_t rex = REX_W; \
	if (sr64 >= R8) \
		rex |= REX_B; \
	if (dr64 >= R8) \
		rex |= REX_R; \
	emit(rex); \
	emit(0x0f); \
	emit(0xaf); \
	emit(ModRM(MOD_VAL, sr64, dr64)); \
} while (0)

/* Compare r64 to zero */
#define IS_ZERO(r64) TEST(r64, r64)

/* Compare r32 to zero */
#define IS_ZERO32(r32) TEST(r32, r32)

/* jcc target */
#define Jcc(cc, target) do { \
	uint32_t o = target - ip - 6; \
	emit(0x0f); \
	emit(0x82 + cc); \
	emit_data(&o, 4); \
} while (0)

/* jcc offset */
#define Jcc_short(cc) \
	ip; \
	SlashR(NA, NA, (0x72 + cc), NA, NA, NA, 0, 1)

#define Jcc_link(jcc_ip) JMP_link(jcc_ip)

/* jmp target */
#define JMP(target) SlashR(NA, NA, 0xe9, NA, NA, NA, target - ip - 5, 4)

/* jmp offset */
#define JMP_short() \
	ip; \
	SlashR(NA, NA, 0xeb, NA, NA, NA, 0, 1)

#define JMP_link(jmp_ip) do { \
	if (pass == PASS_EMIT) \
		jit[jmp_ip + 1] = ip - jmp_ip - 2; \
} while (0)

/* lea [base] + offset into r64 */
#define LEA(base, offset, r64) SlashR(NA, REX(1, r64, NA, base), 0x8d, \
    ModRM(ModForOffset(offset), base, r64), NA, offset, NA, NA)

/* Load [base] + offset into r64 */
#define LOAD(base, offset, r64) SlashR(NA, REX(1, r64, NA, base), 0x8b, \
    ModRM(ModForOffset(offset), base, r64), NA, offset, NA, NA)

/* Load base + offset + scale*index into r64 */
#define LOADsib(base, offset, scale, index, r64) SlashR(NA, \
    REX(1, r64, index, base), 0x8b, \
    ModRM(ModForOffset(offset), RSIB, r64), SIB(scale, index, base), offset, \
    NA, NA)

/* mov sr64, dr64 */
#define MOV(sr64, dr64) SlashR(NA, REX(1, dr64, NA, sr64), 0x8b, \
    ModRM(MOD_VAL, sr64, dr64), NA, NA, NA, NA)

/* mov sr8, dr8 */
#define MOV8(sr8, dr8) SlashR(NA, REX(0, dr8, NA, sr8), 0x8a, \
    ModRM(MOD_VAL, sr8, dr8), NA, NA, NA, NA)

/* movsx sr8, dr64 */
#define MOVSX8(sr8, dr64) do { \
	emit(REX(1, dr64, NA, sr8)); \
	emit(0x0f); \
	emit(0xbe); \
	emit(ModRM(MOD_VAL, sr8, dr64)); \
} while (0)

/* not r64 */
#define NOT(r64) SlashR(NA, REX(1, NA, NA, r64), 0xf7, ModRM(MOD_VAL, r64, 2), \
    NA, NA, NA, NA); \

/* or sr64, dr64 */
#define OR(sr64, dr64) SlashR(NA, REX(1, dr64, NA, sr64), 0x0b, \
    ModRM(MOD_VAL, sr64, dr64), NA, NA, NA, NA)

/* or imm, [base] + offset */
#define ORm32(imm, base, offset) do { \
	if (imm == 0) \
		break; \
	bool is8 = IS8(imm); \
	SlashR(NA, REX(0, NA, NA, base), (is8 ? 0x83 : 0x81), \
	    ModRM(ModForOffset(offset), base, 1), NA, offset, imm, \
	    (is8 ? 1 : 4)); \
} while (0)

/* or imm, [base] + offset */
#define ORm16(imm, base, offset) do { \
	if (imm == 0) \
		break; \
	bool is8 = IS8(imm); \
	SlashR(PREFIX_OPSIZE, REX(0, NA, NA, base), (is8 ? 0x83 : 0x81), \
	    ModRM(ModForOffset(offset), base, 1), NA, offset, imm, \
	    (is8 ? 1 : 2)); \
} while (0)

/* pop r64 */
#define POP(r64) SlashR(NA, REX(0, NA, NA, r64), 0x8f, ModRM(MOD_VAL, r64, 0), \
    NA, NA, NA, NA)

/* push r64 */
#define PUSH(r64) SlashR(NA, REX(0, NA, NA, r64), 0xff, ModRM(MOD_VAL, r64, 6), \
    NA, NA, NA, NA)

/* put r64 into the variable */
#define PUT(r64, var) STORE(r64, RBP, var)

/* put imm into the variable */
#define PUTi(imm, var) STOREi(imm, RBP, var)

/* ret */
#define RET() SlashR(NA, NA, 0xc3, NA, NA, NA, NA, NA)

/* sar shift8, dr64 */
#define SAR(shift8, dr64) do { \
	MOV8(shift8, RCX); \
	SlashR(NA, REX(1, NA, NA, dr64), 0xd3, ModRM(MOD_VAL, dr64, 7), NA, NA, NA, NA); \
} while (0)

/* set r64 to a imm */
#define SET(imm, r64) do { \
	if (imm == 0) { \
		ZERO(r64); \
	} else if (IS32(imm)) { \
		SlashR(NA, REX(1, NA, NA, r64), 0xc7, ModRM(MOD_VAL, r64, 0), \
		    NA, NA, imm, 4);  \
	} else { \
		PlusR(NA, REX(1, NA, NA, r64), 0xb8, r64, imm, 8); \
	} \
} while (0)

/* set r32 to a imm */
#define SET32(imm, r32) do { \
	if (imm == 0) { \
		/* TODO(andrew): only needs 32-bit zero */ \
		ZERO(r32); \
		break; \
	} \
	PlusR(NA, REX(0, NA, NA, r32), 0xb8, r32, imm, 4); \
} while (0)

/* shl shift8, dr64 */
#define SHL(shift8, dr64) do { \
	MOV8(shift8, RCX); \
	SlashR(NA, REX(1, NA, NA, dr64), 0xd3, ModRM(MOD_VAL, dr64, 4), NA, NA, NA, NA); \
} while (0)

/* shr shift8, dr64 */
#define SHR(shift8, dr64) do { \
	MOV8(shift8, RCX); \
	SlashR(NA, REX(1, NA, NA, dr64), 0xd3, ModRM(MOD_VAL, dr64, 5), NA, NA, NA, NA); \
} while (0)

/* store r64 at [base] + offset */
#define STORE(r64, base, offset) SlashR(NA, REX(1, r64, NA, base), 0x89, \
    ModRM(ModForOffset(offset), base, r64), NA, offset, NA, NA)

/* store r64 into base + offset + scale*index */
#define STOREsib(r64, base, offset, scale, index) SlashR(NA, \
    REX(1, r64, index, base), 0x89, \
    ModRM(ModForOffset(offset), RSIB, r64), SIB(scale, index, base), offset, \
    NA, NA)

/* store r32 at [base] + offset */
#define STORE32(r32, base, offset) SlashR(NA, REX(0, r32, NA, base), 0x89, \
    ModRM(ModForOffset(offset), base, r32), NA, offset, NA, NA)

/* store imm at [base] + offset */
#define STOREi(imm, base, offset) SlashR(NA, REX(1, NA, NA, base), 0xc7, \
    ModRM(ModForOffset(offset), base, 0), NA, offset, imm, 4)

/* store imm at [base] + offset */
#define STOREi8(imm, base, offset) SlashR(NA, REX(0, NA, NA, base), 0xc6, \
    ModRM(ModForOffset(offset), base, 0), NA, offset, imm, 1)

/* sub sr64, dr64 */
#define SUB(sr64, dr64) SlashR(NA, REX(1, dr64, NA, sr64), 0x2b, \
    ModRM(MOD_VAL, sr64, dr64), NA, NA, NA, NA)

/* sub imm, r64 */
#define SUBi(imm, r64) do { \
	if (imm == 0) \
		break; \
	bool is8 = IS8(imm); \
	SlashR(NA, REX(1, NA, NA, r64), (is8 ? 0x83 : 0x81), \
	    ModRM(MOD_VAL, r64, 5), NA, NA, imm, (is8 ? 1 : 4)); \
} while (0)

/* test ar64, br64 */
#define TEST(ar64, br64) SlashR(NA, REX(1, ar64, NA, br64), 0x85, \
    ModRM(MOD_VAL, br64, ar64), NA, NA, NA, NA)

/* test ar32, br32 */
#define TEST32(ar32, br32) SlashR(NA, REX(0, ar32, NA, br32), 0x85, \
    ModRM(MOD_VAL, br32, ar32), NA, NA, NA, NA)

/* test [base] + offset, imm */
#define TESTmi16(base, offset, imm) SlashR(NA, REX(1, NA, NA, base), 0xf7, \
    ModRM(ModForOffset(offset), base, 0), NA, offset, imm, 2)

/* xor sr64, dr64 */
#define XOR(sr64, dr64) SlashR(NA, REX(1, dr64, NA, sr64), 0x33, \
    ModRM(MOD_VAL, sr64, dr64), NA, NA, NA, NA)

/* zero out r64 */
#define ZERO(r64) XOR(r64, r64)

/*
 * Compound DIF operations.
 */

#define CANLOAD(reg, sz) do { \
	if (reg == 0) \
		ZERO(FNARG1); \
	else \
		MOV(regs[reg], FNARG1); \
	SET(sz, FNARG2); \
	GET(VAR_MSTATE, FNARG3); \
	GET(VAR_VSTATE, FNARG4); \
	CALL(fns->canload); \
	IS_ZERO32(RAX); \
	uint_t ok_jcc = Jcc_short(JNZ); \
	THROW(); \
	Jcc_link(ok_jcc); \
} while (0)

#define THROW(flag) do { \
	SET32(opc * sizeof(dif_instr_t), RAX); \
	JMP(exception_offset); \
} while(0)

#define THROW_FLAG(flag) do { \
	GET(VAR_FLAGS, RAX); \
	ORm16(flag, RAX, 0); \
	SET32(opc * sizeof(dif_instr_t), RAX); \
	JMP(exception_offset); \
} while(0)

#define THROW_IF_ZERO(r64, flag) do { \
	IS_ZERO(r64); \
	uint_t ok_jcc = Jcc_short(JNZ); \
	THROW_FLAG(flag); \
	Jcc_link(ok_jcc); \
} while (0)

#endif	/* _DTRACE_JIT_ISA_H */
