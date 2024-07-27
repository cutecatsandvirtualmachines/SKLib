#pragma once

#include <immintrin.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if _WIN64 || __x86_64__
    typedef unsigned long long reg_t;
#else
    typedef unsigned long reg_t;
#endif

void __cpuid(int[4], int);
void __cpuidex(int[4], int, int);

void __int2c(void);

unsigned char __inbyte(unsigned short);
unsigned short __inword(unsigned short);
unsigned long __indword(unsigned short);
void __inbytestring(unsigned short, unsigned char*, unsigned long);
void __inwordstring(unsigned short, unsigned short*, unsigned long);
void __indwordstring(unsigned short, unsigned long*, unsigned long);

void __outbyte(unsigned short, unsigned char);
void __outword(unsigned short, unsigned short);
void __outdword(unsigned short, unsigned long);
void __outbytestring(unsigned short, unsigned char*, unsigned long);
void __outwordstring(unsigned short, unsigned short*, unsigned long);
void __outdwordstring(unsigned short, unsigned long*, unsigned long);

void __lidt(void*);
void __sidt(void*);

void _lgdt(void*);
void _sgdt(void*);

unsigned long long __rdtsc(void);
unsigned long long __rdtscp(unsigned int*);

reg_t __readcr0(void);
reg_t __readcr2(void);
reg_t __readcr3(void);
reg_t __readcr4(void);
reg_t __readcr8(void);

void __writecr0(size_t);
void __writecr2(size_t);
void __writecr3(size_t);
void __writecr4(size_t);
void __writecr8(size_t);

size_t __readdr(unsigned int);
void __writedr(unsigned int, size_t);

size_t __readeflags(void);
void __writeeflags(size_t);

unsigned long long __readmsr(unsigned long);
void __writemsr(unsigned long, unsigned long long);

unsigned long long __readpmc(unsigned long);

unsigned long __segmentlimit(unsigned long);

void __invlpg(void*);
void __wbinvd(void);

void __cdecl _disable(void);
void __cdecl _enable(void);

void _rsm(void);

void __halt(void);

void __cdecl __debugbreak(void);
__declspec(noreturn) void __fastfail(unsigned int);

void __svm_clgi(void);
void __svm_invlpga(void*, int);
void __svm_skinit(int);
void __svm_stgi(void);
void __svm_vmload(size_t);
void __svm_vmrun(size_t);
void __svm_vmsave(size_t);
void __svm_invlpgb(void*, int);
void __svm_tlbsync(void);

void __vmx_off(void);
unsigned char __vmx_on(unsigned long long*);
unsigned char __vmx_vmclear(unsigned long long*);
unsigned char __vmx_vmlaunch(void);
unsigned char __vmx_vmptrld(unsigned long long*);
void __vmx_vmptrst(unsigned long long*);
unsigned char __vmx_vmread(size_t, size_t*);
unsigned char __vmx_vmresume(void);
unsigned char __vmx_vmwrite(size_t, size_t);

void __ud2(void);
void __nop(void);

#ifdef __cplusplus
} // extern "C"
#endif