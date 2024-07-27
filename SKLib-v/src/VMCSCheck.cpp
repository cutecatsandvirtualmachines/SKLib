#include "VMCSCheck.h"

CR0 AdjustCr0(CR0 Cr0) {
    CR0 newCr0, fixed0Cr0, fixed1Cr0;

    newCr0 = Cr0;
    fixed0Cr0.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
    fixed1Cr0.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
    newCr0.Flags &= fixed1Cr0.Flags;
    newCr0.Flags |= fixed0Cr0.Flags;
    return newCr0;
}

CR4 AdjustCr4(CR4 Cr4) {
    CR4 newCr4, fixed0Cr4, fixed1Cr4;

    newCr4 = Cr4;
    fixed0Cr4.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
    fixed1Cr4.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
    newCr4.Flags &= fixed1Cr4.Flags;
    newCr4.Flags |= fixed0Cr4.Flags;
    return newCr4;
}

CR0 AdjustGuestCr0(CR0 Cr0) {
    CR0 newCr0;
    IA32_VMX_PROCBASED_CTLS2_REGISTER secondaryProcBasedControls;

    newCr0 = AdjustCr0(Cr0);

    //
    // When the UnrestrictedGuest bit is set, ProtectionEnable and PagingEnable
    // bits are allowed to be zero. Make this adjustment, by setting them 1 only
    // when the guest did indeed requested them to be 1 (ie,
    // Cr0.ProtectionEnable == 1) and the FIXED0 MSR indicated them to be 1 (ie,
    // newCr0.ProtectionEnable == 1).
    //
    __vmx_vmread(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &secondaryProcBasedControls.Flags);
    if (secondaryProcBasedControls.UnrestrictedGuest != FALSE)
    {
        newCr0.ProtectionEnable &= Cr0.ProtectionEnable;
        newCr0.PagingEnable &= Cr0.PagingEnable;
    }
    return newCr0;
}

CR4 AdjustGuestCr4(CR4 Cr4) {
    return AdjustCr4(Cr4);
}

BOOLEAN IsValidGuestPat(UINT64 Pat) {
    return ((Pat == MEMORY_TYPE_UNCACHEABLE) ||
        (Pat == MEMORY_TYPE_WRITE_COMBINING) ||
        (Pat == MEMORY_TYPE_WRITE_THROUGH) ||
        (Pat == MEMORY_TYPE_WRITE_PROTECTED) ||
        (Pat == MEMORY_TYPE_WRITE_BACK) ||
        (Pat == MEMORY_TYPE_UNCACHEABLE_MINUS));
}

void ValidateSegmentAccessRightsHelper(
    SEGMENT_TYPE SegmentType,
    UINT32 AccessRightsAsUInt32,
    UINT32 segmentLimit,
    UINT16 SegmentSelectorAsUInt16,
    BOOLEAN Ia32EModeGuest,
    BOOLEAN UnrestrictedGuest) {

    SEGMENT_SELECTOR selector;
    VMX_SEGMENT_ACCESS_RIGHTS accessRights;
    VMX_SEGMENT_ACCESS_RIGHTS accessRightsSs;
    VMX_SEGMENT_ACCESS_RIGHTS accessRightsCs;
    CR0 cr0;

    selector.Flags = SegmentSelectorAsUInt16;
    accessRights.Flags = AccessRightsAsUInt32;
    __vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, (size_t*)&accessRightsSs.Flags);
    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, (size_t*)&accessRightsCs.Flags);
    __vmx_vmread(VMCS_GUEST_CR0, &cr0.Flags);

    //
    // Bits 3:0 (Type)
    //
    switch (SegmentType)
    {
    case SegmentCs:
        if (UnrestrictedGuest == FALSE)
        {
            ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
        }
        else
        {
            ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
        }
        break;

    case SegmentSs:
        if (accessRights.Unusable == 0)
        {
            ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED));
        }
        break;

    default:
        if (accessRights.Unusable == 0)
        {
            ASSERT(IS_FLAG_SET(accessRights.Type, (1 << 0) /* accessed */));
            if (IS_FLAG_SET(accessRights.Type, (1 << 3) /* code segment */))
            {
                ASSERT(IS_FLAG_SET(accessRights.Type, (1 << 1) /* readable */));
            }
        }
        break;
    }

    //
    // Bit 4 (S)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        ASSERT(accessRights.DescriptorType == 1);
    }

    //
    // Bits 6:5 (DPL)
    //
    switch (SegmentType)
    {
    case SegmentCs:
        switch (accessRights.Type)
        {
        case SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED:
            ASSERT(accessRights.DescriptorPrivilegeLevel == 0);
            break;
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED:
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED:
            ASSERT(accessRights.DescriptorPrivilegeLevel == accessRightsSs.DescriptorPrivilegeLevel);
            break;
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED:
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED:
            ASSERT(accessRights.DescriptorPrivilegeLevel <= accessRightsSs.DescriptorPrivilegeLevel);
            break;
        default:
            ASSERT(FALSE);
        }
        break;

    case SegmentSs:
        if (UnrestrictedGuest == FALSE)
        {
            ASSERT(accessRights.DescriptorPrivilegeLevel == selector.RequestPrivilegeLevel);
        }
        if ((accessRightsCs.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
            (cr0.ProtectionEnable == 1))
        {
            ASSERT(accessRights.DescriptorPrivilegeLevel == 0);
        }
        break;

    default:
        if ((UnrestrictedGuest == FALSE) &&
            (accessRights.Unusable == 0) &&
            (/*(accessRights.Type >= 0) &&*/
                (accessRights.Type <= 11)))
        {
            ASSERT(accessRights.DescriptorPrivilegeLevel >= selector.RequestPrivilegeLevel);
        }
        break;
    }

    //
    // Bit 7 (P)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        ASSERT(accessRights.Present == 1);
    }

    //
    // Bits 11:8 (reserved) and bits 31:17 (reserved)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        ASSERT(accessRights.Reserved1 == 0);
        ASSERT(accessRights.Reserved2 == 0);
    }

    //
    // Bit 14 (D/B)
    //
    if (SegmentType == SegmentCs)
    {
        if ((Ia32EModeGuest != FALSE) &&
            (accessRights.LongMode == 1))
        {
            ASSERT(accessRights.DefaultBig == 0);
        }
    }

    //
    // Bit 15 (G)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        if (!IS_FLAG_SET(segmentLimit, 0xfff))
        {
            ASSERT(accessRights.Granularity == 0);
        }
        if (IS_FLAG_SET(segmentLimit, 0xfff00000))
        {
            ASSERT(accessRights.Granularity == 1);
        }
    }
}

DWORD32 VmRead32(DWORD32 dwVal) {
    size_t tmp;
    __vmx_vmread(dwVal, &tmp);
    return tmp;
}

void Checks::CheckGuestVmcsFieldsForVmEntry()
{
    VMENTRY_INTERRUPT_INFORMATION interruptInfo;
    IA32_VMX_ENTRY_CTLS_REGISTER vmEntryControls;
    IA32_VMX_PINBASED_CTLS_REGISTER pinBasedControls;
    IA32_VMX_PROCBASED_CTLS_REGISTER primaryProcBasedControls;
    IA32_VMX_PROCBASED_CTLS2_REGISTER secondaryProcBasedControls;
    RFLAGS rflags;
    BOOLEAN unrestrictedGuest;
    BOOLEAN bResult = 0;

    bResult |= __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags.Flags);

    bResult |= __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, (size_t*)&interruptInfo.Flags);
    bResult |= __vmx_vmread(VMCS_CTRL_VMENTRY_CONTROLS, &vmEntryControls.Flags);
    bResult |= __vmx_vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, &pinBasedControls.Flags);
    bResult |= __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &primaryProcBasedControls.Flags);
    bResult |= __vmx_vmread(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &secondaryProcBasedControls.Flags);

    unrestrictedGuest = ((primaryProcBasedControls.ActivateSecondaryControls == 1) &&
        (secondaryProcBasedControls.UnrestrictedGuest == 1));

    //
    // 26.3.1.1 Checks on Guest Control Registers, Debug Registers, and MSRs
    //
    CR0 cr0;
    CR4 cr4;
    IA32_DEBUGCTL_REGISTER debugControl;

    bResult |= __vmx_vmread(VMCS_GUEST_CR0, &cr0.Flags);
    bResult |= __vmx_vmread(VMCS_GUEST_CR4, &cr4.Flags);

    ASSERT(cr0.Flags == AdjustGuestCr0(cr0).Flags);
    if ((cr0.PagingEnable == 1) &&
        (unrestrictedGuest == FALSE))
    {
        ASSERT(cr0.ProtectionEnable == 1);
    }
    ASSERT(cr4.Flags == AdjustGuestCr4(cr4).Flags);

    //
    // If bit 23 in the CR4 field (corresponding to CET) is 1, bit 16 in the
    // CR0 field (WP) must also be 1.
    //

    if (vmEntryControls.LoadDebugControls == 1)
    {
        bResult |= __vmx_vmread(VMCS_GUEST_DEBUGCTL, &debugControl.Flags);
        ASSERT(debugControl.Reserved1 == 0);
        ASSERT(debugControl.Reserved2 == 0);
    }
    if (vmEntryControls.Ia32EModeGuest == 1)
    {
        ASSERT(cr0.PagingEnable == 1);
        ASSERT(cr4.PhysicalAddressExtension == 1);
    }
    if (vmEntryControls.LoadDebugControls == 1)
    {
        DR7 dr7;

        bResult |= __vmx_vmread(VMCS_GUEST_DR7, &dr7.Flags);
        ASSERT(dr7.Reserved4 == 0);
    }
    //
    // The IA32_SYSENTER_ESP field and the IA32_SYSENTER_EIP field must each
    // contain a canonical address if the “load CET state” VM-entry control is 1.
    //

    //
    // If the “load IA32_PERF_GLOBAL_CTRL” VM-entry control is 1,
    //
    ASSERT(vmEntryControls.LoadIa32PerfGlobalCtrl == 0);

    if (vmEntryControls.LoadIa32Pat == 1)
    {
        IA32_PAT_REGISTER pat;

        bResult |= __vmx_vmread(VMCS_GUEST_PAT, &pat.Flags);
        ASSERT(IsValidGuestPat(pat.Pa0));
        ASSERT(IsValidGuestPat(pat.Pa1));
        ASSERT(IsValidGuestPat(pat.Pa2));
        ASSERT(IsValidGuestPat(pat.Pa3));
        ASSERT(IsValidGuestPat(pat.Pa4));
        ASSERT(IsValidGuestPat(pat.Pa5));
        ASSERT(IsValidGuestPat(pat.Pa6));
        ASSERT(IsValidGuestPat(pat.Pa7));
    }
    if (vmEntryControls.LoadIa32Efer == 1)
    {
        IA32_EFER_REGISTER efer;

        bResult |= __vmx_vmread(VMCS_GUEST_EFER, &efer.Flags);
        ASSERT(efer.Reserved1 == 0);
        ASSERT(efer.Reserved2 == 0);
        ASSERT(efer.Reserved3 == 0);
        ASSERT(efer.Ia32EModeActive == vmEntryControls.Ia32EModeGuest);
        if (cr0.PagingEnable == 1)
        {
            ASSERT(efer.Ia32EModeActive == efer.Ia32EModeEnable);
        }
    }

    //
    // If the “load IA32_BNDCFGS” VM-entry control is 1,
    //
    ASSERT(vmEntryControls.LoadIa32Bndcfgs == 0);

    //
    // If the “load IA32_RTIT_CTL” VM-entry control is 1,
    //
    ASSERT(vmEntryControls.LoadIa32RtitCtl == 0);

    //
    // If the “load CET state” VM-entry control is 1,
    //
    ASSERT(vmEntryControls.LoadCetState == 0);

    //
    // 26.3.1.2 Checks on Guest Segment Registers
    //
    SEGMENT_SELECTOR selector;
    VMX_SEGMENT_ACCESS_RIGHTS accessRights;
    UINT32 segmentLimit;

    bResult |= __vmx_vmread(VMCS_GUEST_TR_SELECTOR, (size_t*)&selector.Flags);
    ASSERT(selector.Table == 0);

    bResult |= __vmx_vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS, (size_t*)&accessRights.Flags);
    if (accessRights.Unusable == 0)
    {
        bResult |= __vmx_vmread(VMCS_GUEST_LDTR_SELECTOR, (size_t*)&selector.Flags);
        ASSERT(selector.Table == 0);
    }

    if ((rflags.Virtual8086ModeFlag == 0) &&
        (unrestrictedGuest == FALSE))
    {
        SEGMENT_SELECTOR selectorCs;

        bResult |= __vmx_vmread(VMCS_GUEST_CS_SELECTOR, (size_t*)&selectorCs.Flags);
        bResult |= __vmx_vmread(VMCS_GUEST_SS_SELECTOR, (size_t*)&selector.Flags);
        ASSERT(selector.RequestPrivilegeLevel == selectorCs.RequestPrivilegeLevel);
    }
    if (rflags.Virtual8086ModeFlag == 1)
    {
        selector.Flags = (UINT16)VmRead32(VMCS_GUEST_CS_SELECTOR);
        ASSERT(VmRead32(VMCS_GUEST_CS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmRead32(VMCS_GUEST_SS_SELECTOR);
        ASSERT(VmRead32(VMCS_GUEST_SS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmRead32(VMCS_GUEST_DS_SELECTOR);
        ASSERT(VmRead32(VMCS_GUEST_DS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmRead32(VMCS_GUEST_ES_SELECTOR);
        ASSERT(VmRead32(VMCS_GUEST_ES_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmRead32(VMCS_GUEST_FS_SELECTOR);
        ASSERT(VmRead32(VMCS_GUEST_FS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmRead32(VMCS_GUEST_GS_SELECTOR);
        ASSERT(VmRead32(VMCS_GUEST_GS_BASE) == ((UINT64)selector.Index << 4));
    }

    //
    // The following checks are performed on processors that support Intel 64
    // architecture:
    //
    if (rflags.Virtual8086ModeFlag == 1)
    {
        ASSERT(VmRead32(VMCS_GUEST_CS_LIMIT) == 0xffff);
        ASSERT(VmRead32(VMCS_GUEST_SS_LIMIT) == 0xffff);
        ASSERT(VmRead32(VMCS_GUEST_DS_LIMIT) == 0xffff);
        ASSERT(VmRead32(VMCS_GUEST_ES_LIMIT) == 0xffff);
        ASSERT(VmRead32(VMCS_GUEST_FS_LIMIT) == 0xffff);
        ASSERT(VmRead32(VMCS_GUEST_GS_LIMIT) == 0xffff);
    }
    if (rflags.Virtual8086ModeFlag == 1)
    {
        ASSERT(VmRead32(VMCS_GUEST_CS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(VmRead32(VMCS_GUEST_SS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(VmRead32(VMCS_GUEST_DS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(VmRead32(VMCS_GUEST_ES_ACCESS_RIGHTS) == 0xf3);
        ASSERT(VmRead32(VMCS_GUEST_FS_ACCESS_RIGHTS) == 0xf3);
        ASSERT(VmRead32(VMCS_GUEST_GS_ACCESS_RIGHTS) == 0xf3);
    }
    else
    {
        ValidateSegmentAccessRightsHelper(SegmentCs,
            (UINT32)VmRead32(VMCS_GUEST_CS_ACCESS_RIGHTS),
            (UINT32)VmRead32(VMCS_GUEST_CS_LIMIT),
            (UINT16)VmRead32(VMCS_GUEST_CS_SELECTOR),
            (vmEntryControls.Ia32EModeGuest != FALSE),
            unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentSs,
            (UINT32)VmRead32(VMCS_GUEST_SS_ACCESS_RIGHTS),
            (UINT32)VmRead32(VMCS_GUEST_SS_LIMIT),
            (UINT16)VmRead32(VMCS_GUEST_SS_SELECTOR),
            (vmEntryControls.Ia32EModeGuest != FALSE),
            unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentDs,
            (UINT32)VmRead32(VMCS_GUEST_DS_ACCESS_RIGHTS),
            (UINT32)VmRead32(VMCS_GUEST_DS_LIMIT),
            (UINT16)VmRead32(VMCS_GUEST_DS_SELECTOR),
            (vmEntryControls.Ia32EModeGuest != FALSE),
            unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentEs,
            (UINT32)VmRead32(VMCS_GUEST_ES_ACCESS_RIGHTS),
            (UINT32)VmRead32(VMCS_GUEST_ES_LIMIT),
            (UINT16)VmRead32(VMCS_GUEST_ES_SELECTOR),
            (vmEntryControls.Ia32EModeGuest != FALSE),
            unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentFs,
            (UINT32)VmRead32(VMCS_GUEST_FS_ACCESS_RIGHTS),
            (UINT32)VmRead32(VMCS_GUEST_FS_LIMIT),
            (UINT16)VmRead32(VMCS_GUEST_FS_SELECTOR),
            (vmEntryControls.Ia32EModeGuest != FALSE),
            unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentGs,
            (UINT32)VmRead32(VMCS_GUEST_GS_ACCESS_RIGHTS),
            (UINT32)VmRead32(VMCS_GUEST_GS_LIMIT),
            (UINT16)VmRead32(VMCS_GUEST_GS_SELECTOR),
            (vmEntryControls.Ia32EModeGuest != FALSE),
            unrestrictedGuest);
    }

    //
    // TR
    //
    accessRights.Flags = (UINT32)VmRead32(VMCS_GUEST_TR_ACCESS_RIGHTS);
    segmentLimit = (UINT32)VmRead32(VMCS_GUEST_TR_LIMIT);
    if (vmEntryControls.Ia32EModeGuest == 0)
    {
        ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
            (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED));
    }
    else
    {
        ASSERT(accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED);
    }
    ASSERT(accessRights.DescriptorType == 0);
    ASSERT(accessRights.Present == 1);
    ASSERT(accessRights.Reserved1 == 0);
    ASSERT(accessRights.Reserved2 == 0);
    if (!IS_FLAG_SET(segmentLimit, 0xfff))
    {
        ASSERT(accessRights.Granularity == 0);
    }
    if (IS_FLAG_SET(segmentLimit, 0xfff00000))
    {
        ASSERT(accessRights.Granularity == 1);
    }
    ASSERT(accessRights.Unusable == 0);

    //
    // LDTR
    //
    accessRights.Flags = (UINT32)VmRead32(VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    if (accessRights.Unusable == 0)
    {
        segmentLimit = (UINT32)VmRead32(VMCS_GUEST_LDTR_LIMIT);
        ASSERT(accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE);
        ASSERT(accessRights.DescriptorType == 0);
        ASSERT(accessRights.Present == 1);
        ASSERT(accessRights.Reserved1 == 0);
        ASSERT(accessRights.Reserved2 == 0);
        if (!IS_FLAG_SET(segmentLimit, 0xfff))
        {
            ASSERT(accessRights.Granularity == 0);
        }
        if (IS_FLAG_SET(segmentLimit, 0xfff00000))
        {
            ASSERT(accessRights.Granularity == 1);
        }
    }

    //
    // 26.3.1.3 Checks on Guest Descriptor-Table Registers
    //

    //
    // 26.3.1.4 Checks on Guest RIP, RFLAGS, and SSP
    //
    VMX_SEGMENT_ACCESS_RIGHTS csAccessRights;

    bResult |= __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, (size_t*)&csAccessRights.Flags);
    if ((vmEntryControls.Ia32EModeGuest == 0) ||
        (csAccessRights.LongMode == 0))
    {
        ASSERT((VmRead32(VMCS_GUEST_RIP) & ~MAX_UINT16) == 0);
    }

    ASSERT(rflags.Reserved1 == 0);
    ASSERT(rflags.Reserved2 == 0);
    ASSERT(rflags.Reserved3 == 0);
    ASSERT(rflags.Reserved4 == 0);
    ASSERT(rflags.ReadAs1 == 1);
    if ((interruptInfo.Valid == 1) &&
        (interruptInfo.InterruptionType == ExternalInterrupt))
    {
        ASSERT(rflags.InterruptEnableFlag == 1);
    }

    //
    // 26.3.1.5 Checks on Guest Non-Register State
    //
    VMX_INTERRUPTIBILITY_STATE interruptibilityState;
    VMX_GUEST_ACTIVITY_STATE activityState;
    VMX_SEGMENT_ACCESS_RIGHTS ssAccessRights;

    bResult |= __vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, (size_t*)&ssAccessRights.Flags);
    bResult |= __vmx_vmread(VMCS_GUEST_ACTIVITY_STATE, (size_t*)&activityState);
    bResult |= __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, (size_t*)&interruptibilityState.Flags);

    //
    // Activity state
    //
    ASSERT((activityState == VmxActive) ||
        (activityState == VmxHlt) ||
        (activityState == VmxShutdown) ||
        (activityState == VmxWaitForSipi));
    if (ssAccessRights.DescriptorPrivilegeLevel != 0)
    {
        ASSERT(activityState != VmxHlt);
    }
    if ((interruptibilityState.BlockingBySti == 1) ||
        (interruptibilityState.BlockingByMovSs == 1))
    {
        ASSERT(activityState != VmxActive);
    }
    if (interruptInfo.Valid == 1)
    {
        if (activityState == VmxHlt)
        {
            if ((interruptInfo.InterruptionType == ExternalInterrupt) ||
                (interruptInfo.InterruptionType == NonMaskableInterrupt))
            {
                ;
            }
            else if ((interruptInfo.InterruptionType == HardwareException) &&
                ((interruptInfo.list == Debug) ||
                    (interruptInfo.list == MachineCheck)))
            {
                ;
            }
            else if ((interruptInfo.InterruptionType == OtherEvent) &&
                (interruptInfo.list == 0))
            {
                ;
            }
            else
            {
                ASSERT(FALSE);
            }
        }
        else if (activityState == VmxShutdown)
        {
            ASSERT((interruptInfo.list == Nmi) ||
                (interruptInfo.list == MachineCheck));
        }
        else if (activityState == VmxWaitForSipi)
        {
            ASSERT(FALSE);
        }
    }
    if (vmEntryControls.EntryToSmm == 1)
    {
        ASSERT(activityState != VmxWaitForSipi);
    }

    //
    // Interruptibility state
    //
    ASSERT(interruptibilityState.Reserved1 == 0);
    ASSERT((interruptibilityState.BlockingBySti == FALSE) ||
        (interruptibilityState.BlockingByMovSs == FALSE));
    if (rflags.InterruptEnableFlag == 0)
    {
        ASSERT(interruptibilityState.BlockingBySti == 0);
    }
    if ((interruptInfo.Valid == 1) &&
        ((interruptInfo.InterruptionType == ExternalInterrupt) ||
            (interruptInfo.InterruptionType == NonMaskableInterrupt)))
    {
        ASSERT(interruptibilityState.BlockingBySti == 0);
        ASSERT(interruptibilityState.BlockingByMovSs == 0);
    }
    ASSERT(interruptibilityState.BlockingBySmi == 0);
    if (vmEntryControls.EntryToSmm == 1)
    {
        ASSERT(interruptibilityState.BlockingBySmi == 1);
    }
    if ((pinBasedControls.VirtualNmi == 1) &&
        (interruptInfo.Valid == 1) &&
        (interruptInfo.InterruptionType == NonMaskableInterrupt))
    {
        ASSERT(interruptibilityState.BlockingByNmi == 0);
    }
    if (interruptibilityState.EnclaveInterruption == 1)
    {
        ASSERT(interruptibilityState.BlockingByMovSs == 0);
    }

    //
    // Pending debug exceptions checks not implemented
    // VMCS link pointer checks not implemented
    //

    //
    // 26.3.1.6 Checks on Guest Page-Directory-Pointer-Table Entries
    //
    if ((cr0.PagingEnable == 1) &&
        (cr4.PhysicalAddressExtension == 1) &&
        (vmEntryControls.Ia32EModeGuest == 0))
    {
        // Those checks are not implemented.
    }

    if (bResult) {
        DbgMsg("[VMCS] Checks: some VMREADs failed along the way, data may not be correct");
    }
    else {
        DbgMsg("[VMCS] Checks: completed");
    }
}