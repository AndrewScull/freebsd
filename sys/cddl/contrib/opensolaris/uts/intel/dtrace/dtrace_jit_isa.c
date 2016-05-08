#include <sys/dtrace_impl.h>
#include <sys/dtrace_jit_isa.h>

/* The pases */
#define PASS_MEASURE	0
#define PASS_EMIT	1

typedef struct dtrace_jit_analysis_t {
	uint_t used_regs;	/* bitmap of used DTrace integer registers */
	uint_t num_branches;	/* number of branch operations */
	uint_t num_exceptions;	/* number of oprtations that could raise exceptions */
} dtrace_jit_analysis_t;

static struct dtrace_jit_analysis_t
analyse(const dif_instr_t *text, uint_t textlen)
{
	uint_t pc = 0;

	dtrace_jit_analysis_t out = {
		.used_regs = 0,
		.num_branches = 0,
		.num_exceptions = 0,
	};

	while (pc < textlen) {
		dif_instr_t instr = text[pc++];
		uint_t r1 = DIF_INSTR_R1(instr);
		uint_t r2 = DIF_INSTR_R2(instr);
		uint_t rd = DIF_INSTR_RD(instr);

		switch (DIF_INSTR_OP(instr)) {
		case DIF_OP_SDIV:
		case DIF_OP_UDIV:
		case DIF_OP_SREM:
		case DIF_OP_UREM:
		case DIF_OP_COPYS:
			++out.num_exceptions;
			/* FALLTHROUGH */
		case DIF_OP_OR:
		case DIF_OP_XOR:
		case DIF_OP_AND:
		case DIF_OP_SLL:
		case DIF_OP_SRL:
		case DIF_OP_SUB:
		case DIF_OP_ADD:
		case DIF_OP_MUL:
		case DIF_OP_SRA:
			out.used_regs |= (1 << r1) | (1 << r2) | (1 << rd);
			break;

		case DIF_OP_SCMP:
			++out.num_exceptions;
			/* FALLTHROUGH */
		case DIF_OP_CMP:
			out.used_regs |= (1 << r1) | (1 << r2);
			break;

		case DIF_OP_STB:
		case DIF_OP_STH:
		case DIF_OP_STW:
		case DIF_OP_STX:
			++out.num_exceptions;
			/* FALLTHROUGH */
		case DIF_OP_NOT:
		case DIF_OP_MOV:
		case DIF_OP_LDSB:
		case DIF_OP_LDSH:
		case DIF_OP_LDSW:
		case DIF_OP_LDUB:
		case DIF_OP_LDUH:
		case DIF_OP_LDUW:
		case DIF_OP_LDX:
		case DIF_OP_ULDSB:
		case DIF_OP_ULDSH:
		case DIF_OP_ULDSW:
		case DIF_OP_ULDUB:
		case DIF_OP_ULDUH:
		case DIF_OP_ULDUW:
		case DIF_OP_ULDX:
		case DIF_OP_ALLOCS:
			out.used_regs |= (1 << r1) | (1 << rd);
			break;

		case DIF_OP_PUSHTR:
			++out.num_exceptions;
			/* FALLTHROUGH */
		case DIF_OP_LDGA:
			out.used_regs |= (1 << r2) | (1 << rd);
			break;

		case DIF_OP_TST:
		case DIF_OP_RLDSB:
		case DIF_OP_RLDSH:
		case DIF_OP_RLDSW:
		case DIF_OP_RLDUB:
		case DIF_OP_RLDUH:
		case DIF_OP_RLDUW:
		case DIF_OP_RLDX:
			out.used_regs |= (1 << r1);
			break;

		case DIF_OP_LDTA:
		case DIF_OP_LDTS:
		case DIF_OP_STTS:
		case DIF_OP_PUSHTV:
			++out.num_exceptions;
			/* FALLTHROUGH */
		case DIF_OP_RET:
		case DIF_OP_SETX:
		case DIF_OP_SETS:
		case DIF_OP_LDGS:
		case DIF_OP_STGS:
		case DIF_OP_LDLS:
		case DIF_OP_STLS:
		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA:
		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			out.used_regs |= (1 << rd);
			break;

		case DIF_OP_BA:
		case DIF_OP_BE:
		case DIF_OP_BNE:
		case DIF_OP_BG:
		case DIF_OP_BGU:
		case DIF_OP_BGE:
		case DIF_OP_BGEU:
		case DIF_OP_BL:
		case DIF_OP_BLU:
		case DIF_OP_BLE:
		case DIF_OP_BLEU:
			++out.num_branches;
			break;

		case DIF_OP_NOP:
		case DIF_OP_CALL:
		case DIF_OP_POPTS:
		case DIF_OP_FLUSHTS:
			break;

		default:
			ASSERT(0);
			break;
		}
	}

	return out;
}

/*
 * Returns a pointer to a function that must be freed or NULL is unsuccessful.
 */
dtrace_jit_func
dtrace_dif_compile(dtrace_difo_t *difo, dtrace_vstate_t *vstate, dtrace_jit_helpers_t *fns)
{
	ASSERT(difo->dtdo_jit == NULL);
	ASSERT(difo->dtdo_jit_size == 0);

	const dif_instr_t *text = difo->dtdo_buf;
	const uint_t textlen = difo->dtdo_len;
	const char *strtab = difo->dtdo_strtab;
	const uint64_t *inttab = difo->dtdo_inttab;

	const dtrace_jit_analysis_t analysis = analyse(text, textlen);
	const bool has_branch = analysis.num_branches > 0;
	const bool has_exceptions = analysis.num_exceptions > 0;

	uint_t epilogue_offset;
	uint_t exception_offset;
	uint_t *branch_table;

	if (has_branch)
		branch_table = kmem_alloc(textlen * sizeof(uint_t), KM_SLEEP);

	uint64_t rval = 0;
	dtrace_statvar_t *svar;
	dtrace_difv_t *v;

	//dtrace_key_t tupregs[DIF_DTR_NREGS + 2]; /* +2 for thread and id */
	//uint64_t regs[DIF_DIR_NREGS];
	//uint64_t *tmp;

	uint_t pc, id, opc;
	//uint8_t ttop = 0;
	dif_instr_t instr;
	uint_t r1, r2, rd;

	printf("dif {\n");

	uint8_t* jit = NULL;
	uint_t jitlen;
	uint_t ip;
	uint_t jcc, jmp;

	bool dump_plz = false, no_run = false;

	/*
	 * RBX and R12-R15 are callee saved registers. R10 and R11 are not used
	 * as function argumentsregisters but do need to be saved. If changing
	 * this, look for implicit uses related to analysis.used_regs.
	 */
	const uint8_t regs[DIF_DIR_NREGS] = {
	  0xFF, // Always 0 so not a real register
	  R15,
	  R14,
	  R13,
	  R12,
	  RBX,
	  R11,
	  R10,
	};

	// TODO(andrew): these are massive hacks...
#define emit(a) do { \
	if (pass == PASS_EMIT) \
		jit[ip] = a; \
	++ip; \
} while (0)
#define emit_data(ptr, sz) do { \
	if (pass == PASS_EMIT) \
		memcpy(&jit[ip], ptr, sz); \
	ip += sz; \
}	while (0)

	//regs[DIF_REG_R0] = 0; 		/* %r0 is fixed at zero */

	/*
	 * Register %r0 is always 0, so that can use an intermediate.
	 *
	 * Can pass things in as function parameters or put them on the stack.
	 *
	 * There are 8 registers in DIF and there are 8 free registers in x86
	 * after removing those used for function parameters (which is
	 * something that can be looked at again). Since %r0 is always zero it
	 * doesn't need a real register and r9-r15 will be DIF registers 1-9.
	 * Putting them all in the those registers makes it easy to handle the
	 * REX byte at the cost of r9 overlapping with the sizth function
	 * argument.
	 *
	 * The stack will be set up:
	 *
	 * < rbp >
	 * -8  mstate
	 * -16 vstate
	 * -24 state
	 * -32 dstate
	 * -40 flags
	 * -48 illval
	 * tupregs ; 10 entries
	 * < rsp >
	 */

	/*
	 * Now make two passes. The first is the measurement pass which will
	 * find the size the size the instructions will be and save the offset
	 * that operatios will be emitted at. The second pass emits the
	 * instruction into the function buffer.
	 */
	for (int pass = 0; pass < 2; ++pass) {
		if (pass == PASS_EMIT) {
			jit = kmem_alloc(ip, KM_SLEEP);
			if (!jit)
				break;
			jitlen = ip;
		}

		ip = 0;
		pc = 0;

		/* Function prologue to save registers */
		/* TODO(andrew): an optimisation could check which DIF registers are
		 * actually used and so only those registers will have to be saved. */
		PUSH(RBP);
		MOV(RSP, RBP);
		int base_offset = 0;
		for (uint_t i = 1; i < 6; ++i)
			if (analysis.used_regs & (1 << i)) {
				PUSH(regs[i]);
				base_offset -= 8;
			}

		/* Setup the stack frame. */
		// TODO(andrew): Don't always need all of these
		SUBi(VAR_STACK_SIZE, RSP);
		PUT(FNARG2, VAR_MSTATE);
		PUT(FNARG3, VAR_VSTATE);
		PUT(FNARG4, VAR_STATE);
		LEA(FNARG3, offsetof(dtrace_vstate_t, dtvs_dynvars), RAX);
		PUT(RAX, VAR_DSTATE);
		ASSERT(sizeof(((cpu_core_t *)0)->cpuc_dtrace_flags) == 2);
		ADDi(offsetof(cpu_core_t, cpuc_dtrace_flags), FNARG5);
		PUT(FNARG5, VAR_FLAGS);
		ASSERT(sizeof(((cpu_core_t *)0)->cpuc_dtrace_illval) == 8);
		ADDi(offsetof(cpu_core_t, cpuc_dtrace_illval) - offsetof(cpu_core_t, cpuc_dtrace_flags), FNARG5);
		PUT(FNARG5, VAR_ILLVAL);
		PUT(FNARG6, VAR_CURCPU);

		/* TODO(andrew): fill these in correctly
		PUT(FNARG4, VAR_DSTATE);

		mstate->dtms_difo = FNARG1
		*/

		while (pc < textlen) {
			opc = pc;
			if (has_branch)
				branch_table[pc] = ip;

			instr = text[pc++];
			r1 = DIF_INSTR_R1(instr);
			r2 = DIF_INSTR_R2(instr);
			rd = DIF_INSTR_RD(instr);

			switch (DIF_INSTR_OP(instr)) {
			case DIF_OP_OR:
				printf("DIF_OP_OR");
				BinCommOp(OR);
				break;
			case DIF_OP_XOR:
				printf("DIF_OP_XOR\n");
				BinCommOp(XOR);
				break;
			case DIF_OP_AND:
				printf("DIF_OP_AND");
				BinCommOp(AND);
				break;
			case DIF_OP_SLL:
				printf("DIF_OP_SLL");
				ShiftOp(SHL);
				break;
			case DIF_OP_SRL:
				printf("DIF_OP_SRL");
				ShiftOp(SHR);
				break;
			case DIF_OP_SUB:
				printf("DIF_OP_SUB\n");
				if (r2 == 0) {
					MOV(regs[r1], regs[rd]);
				} else if (rd == r1) {
					SUB(regs[r2], regs[rd]);
				} else if (rd == r2) {
					if (r1 == 0)
						ZERO(RAX);
					else
						MOV(regs[r1], RAX);
					SUB(regs[r2], RAX);
					MOV(RAX, regs[rd]);
				} else {
					if (r1 == 0)
						ZERO(regs[rd]);
					else
						MOV(regs[r1], regs[rd]);
					SUB(regs[r2], regs[rd]);
				}
				break;
			case DIF_OP_ADD:
				printf("DIF_OP_ADD\n");
				BinCommOp(ADD);
				break;
			case DIF_OP_MUL:
				printf("DIF_OP_MUL\n");
				BinCommOp(IMUL);
				break;
			case DIF_OP_SDIV:
				printf("DIF_OP_SDIV\n");
				THROW_IF_ZERO(regs[r2], CPU_DTRACE_DIVZERO);
				MOV(regs[r1], RAX);
				IDIV(regs[r2]);
				MOV(RAX, regs[rd]);
				break;
			case DIF_OP_UDIV:
				printf("DIF_OP_UDIV");
				THROW_IF_ZERO(regs[r2], CPU_DTRACE_DIVZERO);
				MOV(regs[r1], RAX);
				DIV(regs[r2]);
				MOV(RAX, regs[rd]);
				break;
			case DIF_OP_SREM:
				printf("DIF_OP_SREM");
				THROW_IF_ZERO(regs[r2], CPU_DTRACE_DIVZERO);
				MOV(regs[r1], RAX);
				IDIV(regs[r2]);
				MOV(RDX, regs[rd]);
				break;
			case DIF_OP_UREM:
				printf("DIF_OP_UREM");
				THROW_IF_ZERO(regs[r2], CPU_DTRACE_DIVZERO);
				MOV(regs[r1], RAX);
				DIV(regs[r2]);
				MOV(RDX, regs[rd]);
				break;

			case DIF_OP_NOT:
				printf("DIF_OP_NOT");
				if (r1 == 0)
					ZERO(regs[rd]);
				else
					MOV(regs[r1], regs[rd]);
				NOT(regs[rd]);
				break;
			case DIF_OP_MOV:
				printf("DIF_OP_MOV\n");
				if (r1 == 0)
					ZERO(regs[rd]);
				else
					MOV(regs[r1], regs[rd]);
				break;
			case DIF_OP_CMP:
				printf("DIF_OP_CMP\n");
				if (r1 == 0 || r2 == 0)
					IS_ZERO(regs[r1 == 0 ? r2 : r1]);
				else
					CMP(regs[r1], regs[r2]);
				break;
			case DIF_OP_TST:
				/* TODO(andrew): This is uterly useless given %r0 is always 0 */
				printf("DIF_OP_TST\n");
				if (r1 == 0) {
					/* xor sets flags properly */
					XOR(regs[r1], regs[r1]);
				} else
					IS_ZERO(regs[r1]);
				break;

			/* TODO(andrew): There is an issue here as architectual
			 * registers get clobbered by instruction whereas the
			 * emulated flags do not..
			 * How do the cc_* flags correspond to arch flags?
			 */
			case DIF_OP_BA:
				printf("DIF_OP_BA\n");
				JMP(branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BE:
				printf("DIF_OP_BE\n");
				Jcc(JE, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BNE:
				printf("DIF_OP_BNE\n");
				Jcc(JNE, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BG:
				printf("DIF_OP_BG\n");
				Jcc(JG, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BGU:
				printf("DIF_OP_BGU\n");
				Jcc(JA, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BGE:
				printf("DIF_OP_BGE\n");
				Jcc(JGE, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BGEU:
				printf("DIF_OP_BGEU\n");
				Jcc(JAE, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BL:
				printf("DIF_OP_BL\n");
				Jcc(JL, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BLU:
				printf("DIF_OP_BLU\n");
				Jcc(JB, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BLE:
				printf("DIF_OP_BLE\n");
				Jcc(JLE, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_BLEU:
				printf("DIF_OP_BLEU\n");
				Jcc(JBE, branch_table[DIF_INSTR_LABEL(instr)]);
				break;
			case DIF_OP_RLDSB:
				CANLOAD(r1, 1);
				/*FALLTHROUGH*/
			case DIF_OP_LDSB:
				/* TODO(andrew): reveal when I have something to test on */
				printf("  Don't know how to compile %s\n", "DIF_OP_RLDSB DIF_OP_LDSB"); goto fail;
				if (r1 == 0)
					ZERO(FNARG1);
				else
					MOV(regs[r1], FNARG1);
				CALL_SAVE();
				CALL(fns->load8);
				CALL_RESTORE();
				GET(VAR_FLAGS, RCX);
				TESTmi16(RCX, 0, CPU_DTRACE_FAULT);
				jcc = Jcc_short(JZ);
				THROW();
				Jcc_link(jcc);
				MOVSX8(RAX, regs[rd]);
				break;
			case DIF_OP_RLDSH:
				CANLOAD(r1, 2);
				/*FALLTHROUGH*/
			case DIF_OP_LDSH:
				printf("  Don't know how to compile %s\n", "DIF_OP_RLDSH DIF_OP_LDSH"); goto fail;
				break;
			case DIF_OP_RLDSW:
				CANLOAD(r1, 4);
				/*FALLTHROUGH*/
			case DIF_OP_LDSW:
				printf("  Don't know how to compile %s\n", "DIF_OP_RLDSW DIF_OP_LDSW"); goto fail;
				break;
			case DIF_OP_RLDUB:
				CANLOAD(r1, 1);
				/*FALLTHROUGH*/
			case DIF_OP_LDUB:
				printf("  Don't know how to compile %s\n", "DIF_OP_RLDUB DIF_OP_LDUB"); goto fail;
				break;
			case DIF_OP_RLDUH:
				CANLOAD(r1, 2);
				/*FALLTHROUGH*/
			case DIF_OP_LDUH:
				printf("  Don't know how to compile %s\n", "DIF_OP_RLDUH DIF_OP_LDUH"); goto fail;
				break;
			case DIF_OP_RLDUW:
				CANLOAD(r1, 4);
				/*FALLTHROUGH*/
			case DIF_OP_LDUW:
				printf("  Don't know how to compile %s\n", "DIF_OP_RLDUW DIF_OP_LDUW"); goto fail;
				break;
			case DIF_OP_RLDX:
				CANLOAD(r1, 8);
				/*FALLTHROUGH*/
			case DIF_OP_LDX:
				printf("  Don't know how to compile %s\n", "DIF_OP_RLDX DIF_OP_LDX"); goto fail;
				break;
			case DIF_OP_ULDSB:
				printf("  Don't know how to compile %s\n", "DIF_OP_ULDSB"); goto fail;
				break;
			case DIF_OP_ULDSH:
				printf("  Don't know how to compile %s\n", "DIF_OP_ULDSH"); goto fail;
				break;
			case DIF_OP_ULDSW:
				printf("  Don't know how to compile %s\n", "DIF_OP_ULDSW"); goto fail;
				break;
			case DIF_OP_ULDUB:
				printf("  Don't know how to compile %s\n", "DIF_OP_ULDUB"); goto fail;
				break;
			case DIF_OP_ULDUH:
				printf("  Don't know how to compile %s\n", "DIF_OP_ULDUH"); goto fail;
				break;
			case DIF_OP_ULDUW:
				printf("  Don't know how to compile %s\n", "DIF_OP_ULDUW"); goto fail;
				break;
			case DIF_OP_ULDX:
				printf("  Don't know how to compile %s\n", "DIF_OP_ULDX"); goto fail;
				break;
			case DIF_OP_RET:
				printf("DIF_OP_RET\n");
				if (rd == 0)
					ZERO(RAX);
				else
					MOV(regs[rd], RAX);
				if (pc != textlen || has_exceptions)
					JMP(epilogue_offset);
				break;
			case DIF_OP_NOP:
				printf("DIF_OP_NOP\n");
				break;
			case DIF_OP_SETX:
				printf("DIF_OP_SETX\n");
				SET(inttab[DIF_INSTR_INTEGER(instr)], regs[rd]);
				break;
			case DIF_OP_SETS:
				printf("DIF_OP_SETS\n");
				SET((uintptr_t)&strtab[DIF_INSTR_STRING(instr)], regs[rd]);
				break;
			case DIF_OP_SCMP: {
				/* TODO(andrew): there is a lot of code here
				 * with dynamic tests so making a function for
				 * this makes a lot of sense. */
				printf("DIF_OP_SCMP\n");
				uint_t jcc2, jcc3;

				IS_ZERO(regs[r1]);
				jcc = Jcc_short(JZ);
				MOV(regs[r1], FNARG1);
				GET(VAR_STATE, RAX);
				LOAD(RAX, offsetof(dtrace_state_t, dts_options)
				    + (DTRACEOPT_STRSIZE * sizeof(dtrace_optval_t)),
				    FNARG2);
				GET(VAR_MSTATE, FNARG3);
				GET(VAR_VSTATE, FNARG4);
				CALL_SAVE();
				CALL(fns->strcanload);
				CALL_RESTORE();
				IS_ZERO32(RAX);
				jcc2 = Jcc_short(JZ);
				Jcc_link(jcc);
				IS_ZERO(regs[r2]);
				jcc = Jcc_short(JZ);
				MOV(regs[r2], FNARG1);
				GET(VAR_STATE, RAX);
				LOAD(RAX, offsetof(dtrace_state_t, dts_options)
				    + (DTRACEOPT_STRSIZE * sizeof(dtrace_optval_t)),
				    FNARG2);
				GET(VAR_MSTATE, FNARG3);
				GET(VAR_VSTATE, FNARG4);
				CALL_SAVE();
				CALL(fns->strcanload);
				CALL_RESTORE();
				IS_ZERO32(RAX);
				jcc3 = Jcc_short(JZ);
				Jcc_link(jcc);
				MOV(regs[r1], FNARG1);
				MOV(regs[r2], FNARG2);
				GET(VAR_STATE, RAX);
				LOAD(RAX, offsetof(dtrace_state_t, dts_options)
				    + (DTRACEOPT_STRSIZE * sizeof(dtrace_optval_t)),
				    FNARG3);
				CALL_SAVE();
				CALL(fns->strncmp);
				CALL_RESTORE();
				IS_ZERO32(RAX);
				jmp = JMP_short();
				Jcc_link(jcc2);
				Jcc_link(jcc3);
				THROW();
				JMP_link(jmp);
				break;
			}
			case DIF_OP_LDGA:
				printf("DIF_OP_LDGA\n");
				GET(VAR_MSTATE, FNARG1);
				GET(VAR_STATE, FNARG2);
				SET(r1, FNARG3);
				MOV(regs[r2], FNARG4);
				CALL_SAVE();
				CALL(fns->dif_variable);
				CALL_RESTORE();
				MOV(RAX, regs[rd]);
				break;
			case DIF_OP_LDGS:
				id = DIF_INSTR_VAR(instr);
				printf("DIF_OP_LDGS[%d]\n", id);

				if (id >= DIF_VAR_OTHER_UBASE) {
					id -= DIF_VAR_OTHER_UBASE;
					svar = vstate->dtvs_globals[id];
					ASSERT(svar != NULL);
					v = &svar->dtsv_var;

					SET((uintptr_t)&svar->dtsv_data, RAX);

					if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
						LOAD(RAX, 0, regs[rd]);
						break;
					}

					printf("  Don't know how to compile %s\n", "DIF_OP_LDGS[^]"); goto fail;
					LOAD(RAX, 0, RAX);
					CMPmi8(RAX, 0,  UINT8_MAX);
					jcc = Jcc_short(JNE);
					ZERO(regs[rd]);
					jmp = JMP_short();
					Jcc_link(jcc);
					ADDi(sizeof(uint64_t), RAX);
					MOV(RAX, regs[rd]);
					JMP_link(jmp);
					break;
				}

				GET(VAR_MSTATE, FNARG1);
				GET(VAR_STATE, FNARG2);
				SET(id, FNARG3);
				ZERO(FNARG4);
				CALL_SAVE();
				CALL(fns->dif_variable);
				CALL_RESTORE();
				MOV(RAX, regs[rd]);
				break;

			case DIF_OP_STGS:
				id = DIF_INSTR_VAR(instr);
				printf("DIF_OP_STGS[%d]\n", id);

				ASSERT(id >= DIF_VAR_OTHER_UBASE);
				id -= DIF_VAR_OTHER_UBASE;

				/* TODO(andrew): rd == 0 */
				svar = vstate->dtvs_globals[id];
				ASSERT(svar != NULL);
				v = &svar->dtsv_var;

				SET((uintptr_t)&svar->dtsv_data, RAX);

				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
					STORE(regs[rd], RAX, 0);
					break;
				}

				printf(" Don't know hot to DIF_OP_STGS[%d]\n", id); goto fail;

				LOAD(RAX, 0, RAX);
				IS_ZERO(regs[rd]);
				jcc = Jcc_short(JNZ);
				STOREi8(UINT8_MAX, RAX, 0);
				jmp = JMP_short();
				STOREi8(0, RAX, 0);
				ADDi(sizeof(uint64_t), RAX);
				/* TODO(andrew): call vcanload and vcopy */
				JMP_link(jmp);

//					if (value == 0) {
//						*(uint8_t *)a = UINT8_MAX;
//						return;
//					}
//
//					*(uint8_t *)a = 0;
//					a += sizeof (uint64_t);
//
//					if (!dtrace_vcanload((void *)(uintptr_t)value, &v->dtdv_type,
//					    mstate, vstate))
//						return;
//
//					dtrace_vcopy((void *)(uintptr_t)value, (void *)a,
//					    &v->dtdv_type);
				break;

			case DIF_OP_LDTA:
				printf("DIF_OP_LDTA");
				THROW_FLAG(CPU_DTRACE_ILLOP);
				break;

			case DIF_OP_LDLS:
				printf("DIF_OP_LDLS\n");
				id = DIF_INSTR_VAR(instr);

				if (id < DIF_VAR_OTHER_UBASE) {
					ZERO(regs[rd]);
					break;
				}

				id -= DIF_VAR_OTHER_UBASE;

				ASSERT(id < vstate->dtvs_nlocals);
				ASSERT(vstate->dtvs_locals != NULL);

				svar = vstate->dtvs_locals[id];
				ASSERT(svar != NULL);
				v = &svar->dtsv_var;

				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
					ASSERT(svar->dtsv_size == NCPU * sizeof (uint64_t));
					SET((uintptr_t)&svar->dtsv_data, RAX);
					LOAD(RAX, 0, RAX);
					GET(VAR_CURCPU, RCX);
					LOADsib(RAX, 0, SIB_8, RCX, regs[rd]);
					break;
				}
				printf("  Don't know how to compile %s\n", "DIF_OP_LTLS"); goto fail;

//				uintptr_t a = (uintptr_t)svar->dtsv_data;
//				size_t sz = v->dtdv_type.dtdt_size;
//
//				sz += sizeof (uint64_t);
//				ASSERT(svar->dtsv_size == NCPU * sz);
//				a += curcpu * sz;
//
//				if (*(uint8_t *)a == UINT8_MAX) {
//					/*
//					 * If the 0th byte is set to UINT8_MAX
//					 * then this is to be treated as a
//					 * reference to a NULL variable.
//					 */
//					regs[rd] = 0;
//				} else {
//					regs[rd] = a + sizeof (uint64_t);
//				}

				break;

			case DIF_OP_STLS:
				printf("DIF_OP_STLS\n");
				id = DIF_INSTR_VAR(instr);

				ASSERT(id >= DIF_VAR_OTHER_UBASE);
				id -= DIF_VAR_OTHER_UBASE;
				ASSERT(id < vstate->dtvs_nlocals);

				ASSERT(vstate->dtvs_locals != NULL);
				svar = vstate->dtvs_locals[id];
				ASSERT(svar != NULL);
				v = &svar->dtsv_var;

				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
					ASSERT(svar->dtsv_size == NCPU * sizeof (uint64_t));
					SET((uintptr_t)&svar->dtsv_data, RAX);
					LOAD(RAX, 0, RAX);
					GET(VAR_CURCPU, RCX);
					if (rd == 0)
						ZERO(RDX);
					STOREsib(rd == 0 ? RDX : regs[rd], RAX, 0, SIB_8, RCX);
					break;
				}
				printf("  Don't know how to compile %s\n", "DIF_OP_STLS"); goto fail;

//				uintptr_t a = (uintptr_t)svar->dtsv_data;
//				size_t sz = v->dtdv_type.dtdt_size;
//
//				sz += sizeof (uint64_t);
//				ASSERT(svar->dtsv_size == NCPU * sz);
//				a += curcpu * sz;
//
//				if (regs[rd] == 0) {
//					*(uint8_t *)a = UINT8_MAX;
//					break;
//				} else {
//					*(uint8_t *)a = 0;
//					a += sizeof (uint64_t);
//				}
//
//				if (!dtrace_vcanload(
//				    (void *)(uintptr_t)regs[rd], &v->dtdv_type,
//				    mstate, vstate))
//					break;
//
//				dtrace_vcopy((void *)(uintptr_t)regs[rd],
//				    (void *)a, &v->dtdv_type);
				break;

			case DIF_OP_LDTS:
				printf("DIF_OP_LDTS\n");

				id = DIF_INSTR_VAR(instr);
				ASSERT(id >= DIF_VAR_OTHER_UBASE);
				id -= DIF_VAR_OTHER_UBASE;
				v = &vstate->dtvs_tlocals[id];

				ZERO(RAX);
				PUT(RAX, VAR_ID_SIZE);
				if (id == 0)
					PUT(RAX, VAR_ID_VALUE);
				else
					PUTi(id, VAR_ID_VALUE);
				PUT(RAX, VAR_THREAD_SIZE);
				CALL_SAVE();
				CALL(fns->tls_thrkey);
				CALL_RESTORE();
				PUT(RAX, VAR_THREAD_VALUE);

				GET(VAR_DSTATE, FNARG1);
				SET(2, FNARG2);
				LEA(RBP, VAR_ID_VALUE, FNARG3);
				SET(sizeof(uint64_t), FNARG4);
				SET(DTRACE_DYNVAR_NOALLOC, FNARG5);
				GET(VAR_MSTATE, FNARG6);
				GET(VAR_VSTATE, RAX);
				CALL_SAVE();
				PUSH(RAX);
				CALL(fns->dynvar);
				ADDi(8, RSP);
				CALL_RESTORE();
				IS_ZERO(RAX);
				jcc = Jcc_short(JNZ);
				/* TODO(andrew): check for CPU flags being set
				 * + other places with call and throw */
				THROW();
				Jcc_link(jcc);
				LOAD(RAX, offsetof(dtrace_dynvar_t, dtdv_data),
				    regs[rd]);
				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF))
					LOAD(regs[rd], 0, regs[rd]);
				break;

			case DIF_OP_STTS:
				printf("DIF_OP_STTS\n");
				id = DIF_INSTR_VAR(instr);
				ASSERT(id >= DIF_VAR_OTHER_UBASE);
				id -= DIF_VAR_OTHER_UBASE;
				v = &vstate->dtvs_tlocals[id];

				ZERO(RAX);
				PUT(RAX, VAR_ID_SIZE);
				if (id == 0)
					PUT(RAX, VAR_ID_VALUE);
				else
					PUTi(id, VAR_ID_VALUE);
				PUT(RAX, VAR_THREAD_SIZE);
				CALL_SAVE();
				CALL(fns->tls_thrkey);
				CALL_RESTORE();
				PUT(RAX, VAR_THREAD_VALUE);

				GET(VAR_DSTATE, FNARG1);
				SET(2, FNARG2);
				LEA(RBP, VAR_ID_VALUE, FNARG3);
				SET(v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
				    v->dtdv_type.dtdt_size : sizeof (uint64_t),
				    FNARG4);
				if (rd != 0) {
					IS_ZERO(regs[rd]);
					jcc = Jcc_short(JZ);
					SET(DTRACE_DYNVAR_ALLOC, FNARG5);
					jmp = JMP_short();
					Jcc_link(jcc);
				}
				SET(DTRACE_DYNVAR_DEALLOC, FNARG5);
				if (rd != 0)
					JMP_link(jmp);
				GET(VAR_MSTATE, FNARG6);
				GET(VAR_VSTATE, RAX);
				CALL_SAVE();
				PUSH(RAX);
				CALL(fns->dynvar);
				ADDi(8, RSP);
				CALL_RESTORE();
				/* TODO(andrew): flush predicate cache?? */
				IS_ZERO(RAX);
				jcc = Jcc_short(JNZ);
				/* TODO(andrew): check for CPU flags being set
				 * + other places with call and throw */
				THROW();
				Jcc_link(jcc);

				LOAD(RAX, offsetof(dtrace_dynvar_t, dtdv_data),
				    RAX);
				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
					STORE(regs[rd], RAX, 0);
					break;
				}

				printf("  Don't know how to compile %s\n", "DIF_OP_STTS"); goto fail;

/*				key = &tupregs[DIF_DTR_NREGS];
				key[0].dttk_value = (uint64_t)id;
				key[0].dttk_size = 0;
				key[1].dttk_value = dtrace_tls_thrkey();
				key[1].dttk_size = 0;

				dvar = dtrace_dynvar(dstate, 2, key,
				    v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
				    v->dtdv_type.dtdt_size : sizeof (uint64_t),
				    regs[rd] ? DTRACE_DYNVAR_ALLOC :
				    DTRACE_DYNVAR_DEALLOC, mstate, vstate);

				*
				 * Given that we're storing to thread-local data,
				 * we need to flush our predicate cache.
				 *
				curthread->t_predcache = 0;

				if (dvar == NULL)
					break;

				if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
					if (!dtrace_vcanload(
					    (void *)(uintptr_t)regs[rd],
					    &v->dtdv_type, mstate, vstate))
						break;

					dtrace_vcopy((void *)(uintptr_t)regs[rd],
					    dvar->dtdv_data, &v->dtdv_type);
				} else {
					*((uint64_t *)dvar->dtdv_data) = regs[rd];
				}

				break; */
				break;

			case DIF_OP_SRA:
				printf("DIF_OP_SRA");
				ShiftOp(SAR);
				break;

			case DIF_OP_CALL:
				printf("  Don't know how to compile %s\n", "DIF_OP_CALL"); goto fail;
				break;

			case DIF_OP_PUSHTR:
				printf("  Don't know how to compile %s\n", "DIF_OP_PUSHTR"); goto fail;
				break;

			case DIF_OP_PUSHTV:
				printf("  Don't know how to compile %s\n", "DIF_OP_PUSHTV"); goto fail;
				break;

			case DIF_OP_POPTS:
				printf("  Don't know how to compile %s\n", "DIF_OP_POPTS"); goto fail;
				break;

			case DIF_OP_FLUSHTS:
				printf("  Don't know how to compile %s\n", "DIF_OP_FLUSHTS"); goto fail;
				break;

			case DIF_OP_LDGAA:
			case DIF_OP_LDTAA:
				printf("  Don't know how to compile %s\n", "DIF_OP_LDGAA DIF_OP_STGAA"); goto fail;
				break;

			case DIF_OP_STGAA:
			case DIF_OP_STTAA:
				printf("  Don't know how to compile %s\n", "DIF_OP_STGAA DIF_OP_STTAA"); goto fail;
				break;

			case DIF_OP_ALLOCS:
				printf("  Don't know how to compile %s\n", "DIF_TF_BYREF"); goto fail;
				break;

			case DIF_OP_COPYS:
				printf("  Don't know how to compile %s\n", "DIF_OP_COPYS"); goto fail;
				break;

			case DIF_OP_STB:
				printf("  Don't know how to compile %s\n", "DIF_OP_STB"); goto fail;
				break;

			case DIF_OP_STH:
				printf("  Don't know how to compile %s\n", "DIF_OP_STH"); goto fail;
				break;

			case DIF_OP_STW:
				printf("  Don't know how to compile %s\n", "DIF_OP_STW"); goto fail;
				break;

			case DIF_OP_STX:
				printf("  Don't know how to compile %s\n", "DIF_OP_STX"); goto fail;
				break;

			default:
				ASSERT(0);
			}
		}

		if (has_exceptions) {
			exception_offset = ip;
			GET(VAR_MSTATE, R9);
			ASSERT(sizeof(((dtrace_mstate_t *)0)->dtms_fltoffs) == 4);
			STORE32(RAX, R9, offsetof(dtrace_mstate_t, dtms_fltoffs));
			ASSERT(sizeof(((dtrace_mstate_t *)0)->dtms_present) == 4);
			ORm32(DTRACE_MSTATE_FLTOFFS, R9,
			    offsetof(dtrace_mstate_t, dtms_present));
			ZERO(RAX);
		}

		/* function epilogue to restore registers */
		epilogue_offset = ip;
		ADDi(VAR_STACK_SIZE, RSP);
		for (uint_t i = 5; i > 0; --i)
			if (analysis.used_regs & (1 << i))
				POP(regs[i]);
		POP(RBP);
		RET();
	}

	if (has_branch)
		kmem_free(branch_table, textlen * sizeof(uint_t));

	// hexdump to console
	if (dump_plz) {
	for (size_t i = 0; i < ip; ++i)
		printf("%hhx ", jit[i]);
	printf("\n");
	}
	if (no_run) {
	kmem_free(jit, jitlen);
	return NULL;
	}

	printf("}\n");

	difo->dtdo_jit = (dtrace_jit_func)jit;
	difo->dtdo_jitlen = jitlen;

	return NULL;

fail:
	if (has_branch)
		kmem_free(branch_table, textlen * sizeof(uint_t));
	if (jit)
		kmem_free(jit, jitlen);
	printf("}\n");
	return NULL;
}
