// Provides MSVC CRT symbols needed by OpenSSL and vpx when linking with Zig's MinGW CRT.

// MSVC's _fltused: linker pulls this in when float operations are present
int _fltused = 0x9875;

// OpenSSL references __setjmp, vpx references _setjmp.
// Implement a minimal x64 setjmp that saves callee-saved registers.
#if defined(__x86_64__) || defined(_M_X64)
// Minimal x64 setjmp: saves rbx, rsp, rbp, rdi, rsi, r12-r15, rip
// jmp_buf layout matches MSVC _JUMP_BUFFER (first 10 slots)
__asm__(
    ".globl __setjmp\n"
    ".globl _setjmp\n"
    "__setjmp:\n"
    "_setjmp:\n"
    "  movq %rbx, 0x00(%rcx)\n"    // Frame
    "  movq %rbp, 0x08(%rcx)\n"    // Rbx (reuse as rbp storage)
    "  movq %r12, 0x10(%rcx)\n"
    "  movq %r13, 0x18(%rcx)\n"
    "  movq %r14, 0x20(%rcx)\n"
    "  movq %r15, 0x28(%rcx)\n"
    "  leaq 0x08(%rsp), %rax\n"    // rsp after return
    "  movq %rax, 0x30(%rcx)\n"    // Rsp
    "  movq (%rsp), %rax\n"        // return address
    "  movq %rax, 0x38(%rcx)\n"    // Rip
    "  movq %rsi, 0x40(%rcx)\n"
    "  movq %rdi, 0x48(%rcx)\n"
    "  xorl %eax, %eax\n"
    "  ret\n"
);
#endif
