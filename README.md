# How to compile
Only prerequisite is

```
vcpkg install
```

inside a vs command prompt.

WDK latest version installed.

## Build
You can find the pre-compiled library in the github action's artifacts.
It is recommended you build the library yourself.

## Note:
Debug compilation target is NOT available. Don't ask questions about it...
## Note 2:
If you get undefined symbols from zydis it's probably because you have installed the wrong version somehow.

# How to use
- Add SKLib-v.lib or SKLib.lib in "Additional Dependencies" in Librarian section for your kernel driver (SKLib-v will automatically link SKLib for you).
- Add your library director
- Add your include directory for SKLib header files in C/C++ -> "Additional Include Directories"

# Usage
This is a basic example of library initialization:
```
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryPath) {
    SKLib::Init();
    DbgMsg("[ENTRY] Current driver name: %ls", SKLib::CurrentDriverName);

    if (!MmIsAddressValid(SKLib::pUserInfo)) {
        DbgMsg("[ENTRY] User info is invalid: %p", SKLib::pUserInfo);
        return SKLIB_USER_INFO_INVALID;
    }
    *SKLib::pUserInfo = *(USERMODE_INFO*)pRegistryPath;

    offsets = SKLib::pUserInfo->offsets;

    winternl::InitImageInfo(pDriverObj);

    identity::Init();

    if (SKLib::pUserInfo->cleanupData.pDriverName[0]) {
        if (SKLib::pUserInfo->cleanupData.hDevice) {
            if (!winternl::ClearMmUnloadedDrivers(SKLib::pUserInfo->cleanupData.hDevice)) {
                DbgMsg("[CLEANUP] MmUnloadedDrivers could not be cleared!");
            }
        }
        if (SKLib::pUserInfo->cleanupData.dwTimestamp) {
            if (!winternl::ClearPIDDBCacheTable(SKLib::pUserInfo->cleanupData.pDriverName, SKLib::pUserInfo->cleanupData.dwTimestamp)) {
                DbgMsg("[CLEANUP] PIDDBCacheTable could not be cleared!");
            }
        }
        if (!winternl::ClearKernelHashBucketList(SKLib::pUserInfo->cleanupData.pDriverName)) {
            DbgMsg("[CLEANUP] KernelHashBucketList could not be cleared!");
        }
    }

    vmm::Init();

    if (!iommu::Init()) {
        DbgMsg("[DMA] Failed initializing DMA protection!");
        return SKLIB_IOMMU_NOT_PRESENT;
    }

    paging::RestoreMapPage();

    winternl::FixSectionPermissions();

    return STATUS_SUCCESS;
}
```

Where the order of the ::Init() methods matters.  

SKLib::Init() should always come first, as well as seting the user info and offsets.  

The basic sample provided performs all needed initialization for all major modules (core, identity map, virtualization, iommuu, etc.) so from there you can look at [a sample driver implementation](https://github.com/cutecatsandvirtualmachines/CheatDriver).  

# Modules

## kdmapper_lib
It's basically kdmapper but as static library for usermode usage, possibly loader development (haven't used it in a while).


## physmeme_lib
physmeme mapper but as static library and with some dumb av driver. Requires driver blocklist to be disabled if you were wondering.


## Pdbparser
Static library dedicated to parsing pdb files, mainly used by me to extract useful offsets for kernel usage and instant portability.
Requires msdia140.dll to be registered to be used.


## SKLib
This is the meat n potatos. It's the core containing various features developed using barebone c++ (the one available in kernel without much tinkering), such as:

- Tracked memory allocations, useful to avoid leaks when doing very sketchy stuff and tracking memory usage is difficult
- Hardware random, pseudo-random, queues, hashmaps, vectors, arrays, strings (CString, Unicode string and WString all in one template class for easy conversions), bitmap and cpu specific helpers, cpp specific stuff from std namespace, threading, disassembler (using zydis)
- PE parser, file and ioctl helpers, windows internal helpers, timers, registry, power, paging (pt parsing, insertion, etc.), IDT parsing and modification, identity map creation (useful for no-driver cheats), ACPI parsing, sharedpool helpers, and codevirtualizer macros

As a whole it consists of a solid core for the main module.


## SKLib-v
This is the real deal I suppose. It leverages SKLib utilities to support the usual hv thing everyone does with cheats, aka system subversion.


A brief list of features and important details:

- AMD and Intel hypervisors
- Missing nested virtualization and all that extra stuff no one ever does
- AMD and Intel fast SLAT based hooks, none of that breakpoint like stuff, so it has some limitations but it's fast enough to have no noticeable performance hit at dozen of SLAT hooks. (note: EPT namespace contains code for both Intel and AMD although a misleading name)
- IOMMU and VT-d subversion for DMA protection
- SMBIOS, GPU, NIC, Volume, Disk, Monitor, USB and EFI spoofers (working as of last tests 2 months ago on EAC)
- Customizeable vmcall interface, as well as some other internal interfaces you can use to customize vmx-root behavior at runtime.
- vmx-root error handling (very limited and broken and pasted but cba to fix it properly)

## Conclusion
This is not a complete list of features or disclaimers that would be needed for proper long term support. 
The library is mainly focused on highly specific research tools and not on production grade code.

I'll be happy to assist with major issues if needed though, so feel free open an issue on this repo.
