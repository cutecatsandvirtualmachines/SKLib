#pragma once
#include "cpp.h"

NTSTATUS CreateStandardSCAndACL(OUT PSECURITY_DESCRIPTOR* SecurityDescriptor, OUT PACL* Acl);
NTSTATUS GrantAccess(HANDLE hSection, IN PACL StandardAcl);