#pragma once

#include "cpp.h"
#include "MemoryEx.h"
#include "signatures.h"
#include "acpi.h"
#include "EPT.h"

#ifdef _KERNEL_MODE

#pragma pack(1)

/*
* IOMMU capability definition structures
*/

typedef struct {
    DWORD32 CapId : 8;
    DWORD32 CapPtr : 8;
    DWORD32 CapType : 3;
    DWORD32 CapRev : 5;
    DWORD32 IotlbSup : 1;
    DWORD32 HtTunnel : 1;
    DWORD32 NpCache : 1;
    DWORD32 EFRSup : 1;
    DWORD32 CapExt : 1;
    DWORD32 Reserved : 3;
} IOMMU_CAPABILITY_HEADER, * PIOMMU_CAPABILITY_HEADER;

typedef struct {
    DWORD32 Enable : 1;
    DWORD32 Reserved : 13;
    DWORD32 BaseAddress_18_14 : 5;
    DWORD32 BaseAddress_31_19 : 13;
} IOMMU_BASE_ADDRESS_LOW_REGISTER, * PIOMMU_BASE_ADDRESS_LOW_REGISTER;

typedef DWORD32 IOMMU_BASE_ADDRESS_HIGH_REGISTER, * PIOMMU_BASE_ADDRESS_HIGH_REGISTER;

typedef struct {
    DWORD32 UnitID : 5;
    DWORD32 Reserved : 2;
    DWORD32 RngValid : 1;
    DWORD32 BusNumber : 8;
    DWORD32 FirstDevice : 8;
    DWORD32 LastDevice : 8;
} IOMMU_RANGE_REGISTER, * PIOMMU_RANGE_REGISTER;

typedef struct {
    DWORD32 MsiNum : 5;
    DWORD32 GVAsize : 3;
    DWORD32 PAsize : 7;
    DWORD32 VAsize : 7;
    DWORD32 HtAtsResv : 1;
    DWORD32 Reserved : 4;
    DWORD32 MsiNumPPR : 5;
} IOMMU_MISCELLANEOUS_INFO_REGISTER, * PIOMMU_MISCELLANEOUS_INFO_REGISTER;

typedef struct {
    DWORD32 MsiNumGA : 5;
    DWORD32 Reserved : 27;
} IOMMU_MISCELLANEOUS_INFO_REGISTER_1, * PIOMMU_MISCELLANEOUS_INFO_REGISTER_1;

typedef struct {
    IOMMU_CAPABILITY_HEADER header;
    IOMMU_BASE_ADDRESS_LOW_REGISTER baseAddressLow;
    IOMMU_BASE_ADDRESS_HIGH_REGISTER baseAddressHigh;
    IOMMU_RANGE_REGISTER rangeReg;
    IOMMU_MISCELLANEOUS_INFO_REGISTER miscInfoReg;
    IOMMU_MISCELLANEOUS_INFO_REGISTER_1 miscInfoReg1;
} IOMMU_CAP_BLOCK_REGISTER, * PIOMMU_CAP_BLOCK_REGISTER;

/*
* IOMMU vendor specific structures
*/
typedef struct {
    DWORD32 CapID : 8;
    DWORD32 CapPtr : 8;
    DWORD32 CapLen : 8;
    DWORD32 CapType : 8;
} IOMMU_VENDOR_SPECIFIC_CAP_HEADER, * PIOMMU_VENDOR_SPECIFIC_CAP_HEADER;

typedef struct {
    DWORD32 VSC_ID : 16;
    DWORD32 VSC_Rev : 8;
    DWORD32 Reserved : 8;
} IOMMU_VENDOR_SPECIFIC_CAP_INFO, * PIOMMU_VENDOR_SPECIFIC_CAP_INFO;

typedef struct {
    DWORD32 VF_Enable : 1;
    DWORD32 Reserved : 27;
    DWORD32 VF_BaseAddress : 4;
} IOMMU_VENDOR_SPECIFIC_VF_BASE_LOW, * PIOMMU_VENDOR_SPECIFIC_VF_BASE_LOW;

typedef DWORD32 IOMMU_VENDOR_SPECIFIC_VF_BASE_HIGH, * PIOMMU_VENDOR_SPECIFIC_VF_BASE_HIGH;

typedef struct {
    DWORD32 VF_Enable : 1;
    DWORD32 Reserved : 21;
    DWORD32 VF_BaseAddress : 10;
} IOMMU_VENDOR_SPECIFIC_VF_CONTROL_BASE_LOW, * PIOMMU_VENDOR_SPECIFIC_VF_CONTROL_BASE_LOW;

typedef DWORD32 IOMMU_VENDOR_SPECIFIC_VF_CONTROL_BASE_HIGH, * PIOMMU_VENDOR_SPECIFIC_VF_CONTROL_BASE_HIGH;

typedef struct {
    IOMMU_VENDOR_SPECIFIC_CAP_HEADER header;
    IOMMU_VENDOR_SPECIFIC_CAP_INFO info;
    IOMMU_VENDOR_SPECIFIC_VF_BASE_LOW virtFuncBaseLow;
    IOMMU_VENDOR_SPECIFIC_VF_BASE_HIGH virtFuncBaseHigh;
    IOMMU_VENDOR_SPECIFIC_VF_CONTROL_BASE_LOW virtFuncCtlLow;
    IOMMU_VENDOR_SPECIFIC_VF_CONTROL_BASE_HIGH virtFuncCtlHigh;
} IOMMU_VENDOR_SPECIFIC_BLOCK_REGISTER, * PIOMMU_VENDOR_SPECIFIC_BLOCK_REGISTER;

/*
* IOMMU MMIO structures
*/
typedef struct {
    DWORD64 Size : 9;
    DWORD64 Reserved1 : 3;
    DWORD64 DevTabBase : 40;
    DWORD64 Reserved2 : 12;
} IOMMU_MMIO_DT_BASE_REGISTER, * PIOMMU_MMIO_DT_BASE_REGISTER;

typedef struct {
    DWORD64 Reserved1 : 12;
    DWORD64 ComBase : 40;
    DWORD64 Reserved2 : 4;
    DWORD64 ComLen : 4;
    DWORD64 Reserved3 : 4;
} IOMMU_MMIO_CMD_BASE_REGISTER, * PIOMMU_MMIO_CMD_BASE_REGISTER;

typedef struct {
    DWORD64 Reserved1 : 12;
    DWORD64 EventBase : 40;
    DWORD64 Reserved2 : 4;
    DWORD64 EventLen : 4;
    DWORD64 Reserved3 : 4;
} IOMMU_MMIO_LOG_BASE_REGISTER, * PIOMMU_MMIO_LOG_BASE_REGISTER;

typedef struct {
    DWORD64 IommuEn : 1;
    DWORD64 HtTunEn : 1;
    DWORD64 EventLogEn : 1;
    DWORD64 EventIntEn : 1;
    DWORD64 ComWaitIntEn : 1;
    DWORD64 InvTimeOut : 3;
    DWORD64 PassPW : 1;
    DWORD64 ResPassPW : 1;
    DWORD64 Coherent : 1;
    DWORD64 Isoc : 1;
    DWORD64 CmdBufEn : 1;
    DWORD64 PPRLogEn : 1;
    DWORD64 PprIntEn : 1;
    DWORD64 PPREn : 1;
    DWORD64 GTEn : 1;
    DWORD64 GAEn : 1;
    DWORD64 CRW : 4;
    DWORD64 SmiFEn : 1;
    DWORD64 SlfWBdis : 1;
    DWORD64 SmiFLogEn : 1;
    DWORD64 GAMEn : 3;
    DWORD64 GALogEn : 1;
    DWORD64 GAIntEn : 1;
    DWORD64 DualPprLogEn : 2;
    DWORD64 DualEventLogEn : 2;
    DWORD64 DevTblSegEn : 3;
    DWORD64 PrivAbrtEn : 2;
    DWORD64 PprAutoRspEn : 1;
    DWORD64 MarcEn : 1;
    DWORD64 BlkStopMrkEn : 1;
    DWORD64 PprAutoRspAon : 1;
    DWORD64 Reserved1 : 2;
    DWORD64 EPHEn : 1;
    DWORD64 HADUpdate : 2;
    DWORD64 GDUpdateDis : 1;
    DWORD64 Reserved2 : 1;
    DWORD64 XTEn : 1;
    DWORD64 IntCapXTEn : 1;
    DWORD64 vCmdEn : 1;
    DWORD64 vIommuEn : 1;
    DWORD64 GAUpdateDis : 1;
    DWORD64 GAPPIEn : 1;
    DWORD64 Reserved3 : 2;
    DWORD64 GCR3TRPMode : 1;
    DWORD64 IRTCacheDis : 1;
    DWORD64 GstBufferTRPMode : 1;
    DWORD64 SNPAVICEn : 3;
} IOMMU_MMIO_CTRL_REGISTER, * PIOMMU_MMIO_CTRL_REGISTER;

typedef struct {
    DWORD64 ExEn : 1;
    DWORD64 Allow : 1;
    DWORD64 Reserved : 10;
    DWORD64 ExclRangeBaseAddr : 40;
    DWORD64 Reserved1 : 12;
} IOMMU_MMIO_EXCL_BASE_REGISTER, * PIOMMU_MMIO_EXCL_BASE_REGISTER;

typedef struct {
    DWORD64 Reserved : 12;
    DWORD64 ExclRangeLimit : 40;
    DWORD64 Reserved1 : 12;
} IOMMU_MMIO_EXCL_LIMIT_REGISTER, * PIOMMU_MMIO_EXCL_LIMIT_REGISTER;

typedef struct {
    DWORD64 PreFSup : 1;
    DWORD64 PPRSup : 1;
    DWORD64 XTSup : 1;
    DWORD64 NXSup : 1;
    DWORD64 GTSup : 1;
    DWORD64 GAPPISup : 1;
    DWORD64 IASup : 1;
    DWORD64 GASup : 1;
    DWORD64 HESup : 1;
    DWORD64 PCSup : 1;
    DWORD64 HATS : 2;
    DWORD64 GATS : 2;
    DWORD64 GLXSup : 2;
    DWORD64 SmiFSup : 2;
    DWORD64 SmiFRC : 3;
    DWORD64 GAMSup : 3;
    DWORD64 DualPprLogSup : 2;
    DWORD64 Reserved11 : 2;
    DWORD64 DualEventLogSup : 2;
    DWORD64 Reserved12 : 1;
    DWORD64 SATSSup : 1;
    DWORD64 PASmax : 5;
    DWORD64 USSup : 1;
    DWORD64 DevTblSegSup : 2;
    DWORD64 PprOvrflwEarlySup : 1;
    DWORD64 PPRAutoRspSup : 1;
    DWORD64 MarcSup : 2;
    DWORD64 BlkStopMrkSup : 1;
    DWORD64 PerfOptSup : 1;
    DWORD64 MsiCapMmioSup : 1;
    DWORD64 Reserved3 : 1;
    DWORD64 GIoSup : 1;
    DWORD64 HASup : 1;
    DWORD64 EPHSup : 1;
    DWORD64 AttrFWSup : 1;
    DWORD64 HDSup : 1;
    DWORD64 Reserved4 : 1;
    DWORD64 InvIotlbTypeSup : 1;
    DWORD64 vIommuSup : 1;
    DWORD64 Reserved5 : 5;
    DWORD64 GAUpdateDisSup : 1;
    DWORD64 ForcePhyDestSup : 1;
    DWORD64 SNPSup : 1;
} IOMMU_MMIO_EXT_FEAT_REGISTER, * PIOMMU_MMIO_EXT_FEAT_REGISTER;

typedef struct {
    IOMMU_MMIO_DT_BASE_REGISTER devTableBaseReg;
    IOMMU_MMIO_CMD_BASE_REGISTER cmdBaseReg;
    IOMMU_MMIO_LOG_BASE_REGISTER logBaseReg;
    IOMMU_MMIO_CTRL_REGISTER ctrlReg;
    IOMMU_MMIO_EXCL_BASE_REGISTER exclBaseReg;
    IOMMU_MMIO_EXCL_LIMIT_REGISTER exclLimitReg;
    IOMMU_MMIO_EXT_FEAT_REGISTER extFeatReg;
} IOMMU_MMIO, * PIOMMU_MMIO;

typedef struct {
    struct {
        DWORD64 V : 1;
        DWORD64 TV : 1;
        DWORD64 Reserved1 : 5;
        DWORD64 HAD : 2;
        DWORD64 PagingMode : 3;
        DWORD64 PageTableRootPtr : 40;
        DWORD64 PPR : 1;
        DWORD64 GPRP : 1;
        DWORD64 GIoV : 1;
        DWORD64 GV : 1;
        DWORD64 GLX : 2;
        DWORD64 GCR3 : 3;
        DWORD64 IR : 1;
        DWORD64 IW : 1;
        DWORD64 Reserved2 : 1;
    } _63_0;
    struct {
        DWORD64 DomainID : 16;
        DWORD64 GCR3_30_15 : 16;
        DWORD64 IOTLBe : 1;
        DWORD64 SE : 1;
        DWORD64 SA : 1;
        DWORD64 IoCtl : 2;
        DWORD64 Cache : 1;
        DWORD64 SD : 1;
        DWORD64 EX : 1;
        DWORD64 SysMgt : 2;
        DWORD64 SATS : 1;
        DWORD64 GCR3_51_31 : 21;
    } _127_64;
    struct {
        DWORD64 IV : 1;
        DWORD64 IntTabLen : 4;
        DWORD64 IG : 1;
        DWORD64 InterruptTableRoot : 46;
        DWORD64 Reserved3 : 2;
        DWORD64 GuestPagingMode : 2;
        DWORD64 InitPass : 1;
        DWORD64 EIntPass : 1;
        DWORD64 NMIPass : 1;
        DWORD64 HPTMode : 1;
        DWORD64 IntCtl : 2;
        DWORD64 Lint0Pass : 1;
        DWORD64 Lint1Pass : 1;
    } _191_128;
    struct {
        DWORD64 Reserved4 : 15;
        DWORD64 vImuEn : 1;
        DWORD64 GDeviceID : 16;
        DWORD64 GuestID : 16;
        DWORD64 Reserved5 : 5;
        DWORD64 Reserved6 : 1;
        DWORD64 AttrV : 1;
        DWORD64 Mode0FC : 1;
        DWORD64 SnoopAttribute : 8;
    } _255_192;
} IOMMU_DEVICE_TABLE_ENTRY, * PIOMMU_DEVICE_TABLE_ENTRY;

typedef struct {
    DWORD64 Reserved1 : 4;
    DWORD64 CmdHeadPtr : 15;
    DWORD64 Reserved2 : 45;
} IOMMU_CMD_BUFFER_HEAD_REGISTER, * PIOMMU_CMD_BUFFER_HEAD_REGISTER;

typedef struct {
    DWORD64 Reserved1 : 4;
    DWORD64 CmdTailPtr : 15;
    DWORD64 Reserved2 : 45;
} IOMMU_CMD_BUFFER_TAIL_REGISTER, * PIOMMU_CMD_BUFFER_TAIL_REGISTER;

typedef struct {
    DWORD64 opcodeDependantOperand1_31_0 : 32;
    DWORD64 opcodeDependantOperand1_59_32 : 28;
    DWORD64 cmdCode : 4;
    DWORD64 opcodeDependantOperand2;
} IOMMU_GENERIC_CMD, * PIOMMU_GENERIC_CMD;

typedef struct {
    DWORD64 Reserved1 : 4;
    DWORD64 LogHeadPtr : 15;
    DWORD64 Reserved2 : 45;
} IOMMU_LOG_BUFFER_HEAD_REGISTER, * PIOMMU_LOG_BUFFER_HEAD_REGISTER;

typedef struct {
    DWORD64 Reserved1 : 4;
    DWORD64 LogTailPtr : 15;
    DWORD64 Reserved2 : 45;
} IOMMU_LOG_BUFFER_TAIL_REGISTER, * PIOMMU_LOG_BUFFER_TAIL_REGISTER;

typedef struct {
    DWORD64 opcodeDependantOperand1_31_0 : 32;
    DWORD64 opcodeDependantOperand1_59_32 : 28;
    DWORD64 evtCode : 4;
    DWORD64 opcodeDependantOperand2;
} IOMMU_GENERIC_LOG, * PIOMMU_GENERIC_LOG;

typedef struct {
    DWORD64 EventOverflow : 1;
    DWORD64 EventLogInt : 1;
    DWORD64 ComWaitInt : 1;
    DWORD64 EventLogRun : 1;
    DWORD64 CmdBufRun : 1;
    DWORD64 PprOverflow : 1;
    DWORD64 PprInt : 1;
    DWORD64 PPRLogRun : 1;
    DWORD64 GALogRun : 1;
    DWORD64 GALOverflow : 1;
    DWORD64 GAInt : 1;
    DWORD64 PprOvrflwB : 1;
    DWORD64 PprLogActive : 1;
    DWORD64 Reserved1 : 2;
    DWORD64 EventOvrflwB : 1;
    DWORD64 EventLogActive : 1;
    DWORD64 PprOvrflwEarlyB : 1;
    DWORD64 PprOvrflwEarly : 1;
    DWORD64 Reserved2 : 45;
} IOMMU_CMD_STATUS_REGISTER, * PIOMMU_CMD_STATUS_REGISTER;

typedef struct {
    DWORD64 PASID : 20;
    DWORD64 Reserved1 : 12;
    DWORD64 DomainID : 16;
    DWORD64 Reserved2 : 12;
    DWORD64 cmdCode : 4;
    DWORD64 S : 1;
    DWORD64 PDE : 1;
    DWORD64 GE : 1;
    DWORD64 Reserved3 : 9;
    DWORD64 Address : 52;
} IOMMU_INVALIDATE_IOMMU_PAGES, * PIOMMU_INVALIDATE_IOMMU_PAGES;

typedef struct {
    DWORD64 DeviceID : 16;
    DWORD64 Reserved1 : 44;
    DWORD64 cmdCode : 4;
    DWORD64 Reserved2;
} IOMMU_INVALIDATE_DEVTAB_ENTRY, * PIOMMU_INVALIDATE_DEVTAB_ENTRY;

#define INVALIDATE_DEVTAB_ENTRY 0x2
#define INVALIDATE_IOMMU_PAGES 0x3
#define INVALIDATE_IOMMU_ALL 0x8

#define CMD_BUFFER_HEAD_REGISTER_OFFSET 0x2000
#define CMD_BUFFER_TAIL_REGISTER_OFFSET 0x2008
#define CMD_LOG_HEAD_REGISTER_OFFSET 0x2010
#define CMD_LOG_TAIL_REGISTER_OFFSET 0x2018
#define CMD_STATUS_REGISTER_OFFSET 0x2020

#define IOMMU_PAGE_TABLES_LEVELS 4
#define IOMMU_PAGE_TABLES_ENTRIES 512

typedef union {
    struct {
        DWORD64 PR : 1;
        DWORD64 Reserved1 : 4;
        DWORD64 A : 1;
        DWORD64 D : 1;
        DWORD64 Reserved2 : 2;
        DWORD64 NextLevel : 3;
        DWORD64 PageAddress : 40;
        DWORD64 Reserved3 : 7;
        DWORD64 U : 1;
        DWORD64 FC : 1;
        DWORD64 IR : 1;
        DWORD64 IW : 1;
        DWORD64 Reserved4 : 1;
    } bits;
    DWORD64 Flags;
} IOMMU_PTE, * PIOMMU_PTE;

typedef struct {
    DECLSPEC_ALIGN(PAGE_SIZE) IOMMU_PTE level4[IOMMU_PAGE_TABLES_ENTRIES];
    DECLSPEC_ALIGN(PAGE_SIZE) IOMMU_PTE level3[IOMMU_PAGE_TABLES_ENTRIES];
    DECLSPEC_ALIGN(PAGE_SIZE) IOMMU_PTE level2[IOMMU_PAGE_TABLES_ENTRIES][IOMMU_PAGE_TABLES_ENTRIES];
} IOMMU_PAGE_TABLES, *PIOMMU_PAGE_TABLES;

#pragma pack()
namespace iommu {
    bool Init();

    PIOMMU_PAGE_TABLES CreateIommuPageTables();
    bool HidePage(PVOID pTarget, PVOID pSubstitute = nullptr, BOOLEAN bInvalidateIotlb = FALSE);
    bool HidePageRange(PVOID pBase, SIZE_T szRegion, PVOID pSubstitute = nullptr);
    bool BlockPage(PVOID pTarget, BOOLEAN bInvalidateIotlb = FALSE);
    bool BlockPageRange(PVOID pBase, SIZE_T szRegion);

    void EnableIommu();
}

#endif