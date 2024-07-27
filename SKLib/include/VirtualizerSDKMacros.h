/****************************************************************************** 
  Header: VirtualizerMacros.h
  Description: Definition of SecureEngine macros via ASM module

  Author/s: Oreans Technologies  
  (c) 2013 Oreans Technologies
*****************************************************************************/ 

#pragma once

#include "macros.h"


// ***********************************************
// Specify platform
// ***********************************************

#ifdef _WIN64
#define PLATFORM_X64
#else
#define PLATFORM_X32
#endif


// ***********************************************
// Include files
// ***********************************************

#include "VirtualizerSDKCustomVMsMacros.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PROTECT_BINARY
#if defined(PLATFORM_X32)

void __stdcall VIRTUALIZER_START_ASM32();
void __stdcall VIRTUALIZER_END_ASM32();
void __stdcall VIRTUALIZER_STR_ENCRYPT_START_ASM32();
void __stdcall VIRTUALIZER_STR_ENCRYPT_END_ASM32();
void __stdcall VIRTUALIZER_STR_ENCRYPTW_START_ASM32();
void __stdcall VIRTUALIZER_STR_ENCRYPTW_END_ASM32();
void __stdcall VIRTUALIZER_UNPROTECTED_START_ASM32();
void __stdcall VIRTUALIZER_UNPROTECTED_END_ASM32();

#define VIRTUALIZER_START VIRTUALIZER_START_ASM32();
#define VIRTUALIZER_END VIRTUALIZER_END_ASM32();
#define VIRTUALIZER_STR_ENCRYPT_START VIRTUALIZER_STR_ENCRYPT_START_ASM32();
#define VIRTUALIZER_STR_ENCRYPT_END VIRTUALIZER_STR_ENCRYPT_END_ASM32();
#define VIRTUALIZER_STR_ENCRYPTW_START VIRTUALIZER_STR_ENCRYPTW_START_ASM32();
#define VIRTUALIZER_STR_ENCRYPTW_END VIRTUALIZER_STR_ENCRYPTW_END_ASM32();
#define VIRTUALIZER_UNPROTECTED_START VIRTUALIZER_UNPROTECTED_START_ASM32();
#define VIRTUALIZER_UNPROTECTED_END VIRTUALIZER_UNPROTECTED_END_ASM32();

#endif 

#if defined(PLATFORM_X64)

void __stdcall VIRTUALIZER_START_ASM64();
void __stdcall VIRTUALIZER_END_ASM64();
void __stdcall VIRTUALIZER_STR_ENCRYPT_START_ASM64();
void __stdcall VIRTUALIZER_STR_ENCRYPT_END_ASM64();
void __stdcall VIRTUALIZER_STR_ENCRYPTW_START_ASM64();
void __stdcall VIRTUALIZER_STR_ENCRYPTW_END_ASM64();
void __stdcall VIRTUALIZER_UNPROTECTED_START_ASM64();
void __stdcall VIRTUALIZER_UNPROTECTED_END_ASM64();

#define VIRTUALIZER_START VIRTUALIZER_START_ASM64();
#define VIRTUALIZER_END VIRTUALIZER_END_ASM64();
#define VIRTUALIZER_STR_ENCRYPT_START VIRTUALIZER_STR_ENCRYPT_START_ASM64();
#define VIRTUALIZER_STR_ENCRYPT_END VIRTUALIZER_STR_ENCRYPT_END_ASM64();
#define VIRTUALIZER_STR_ENCRYPTW_START VIRTUALIZER_STR_ENCRYPTW_START_ASM64();
#define VIRTUALIZER_STR_ENCRYPTW_END VIRTUALIZER_STR_ENCRYPTW_END_ASM64();
#define VIRTUALIZER_UNPROTECTED_START VIRTUALIZER_UNPROTECTED_START_ASM64();
#define VIRTUALIZER_UNPROTECTED_END VIRTUALIZER_UNPROTECTED_END_ASM64();

#endif
#else

#define VIRTUALIZER_START
#define VIRTUALIZER_END
#define VIRTUALIZER_STR_ENCRYPT_START
#define VIRTUALIZER_STR_ENCRYPT_END
#define VIRTUALIZER_STR_ENCRYPTW_START
#define VIRTUALIZER_STR_ENCRYPTW_END
#define VIRTUALIZER_UNPROTECTED_START
#define VIRTUALIZER_UNPROTECTED_END

#endif

#ifdef __cplusplus
}
#endif