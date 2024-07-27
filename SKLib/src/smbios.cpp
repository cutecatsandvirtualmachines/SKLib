#include "smbios.h"

#define DMI_READ_8U    *ptr_++
#define DMI_READ_16U   *((SHORT*)ptr_), ptr_ += 2
#define DMI_READ_32U   *((DWORD32*)ptr_), ptr_ += 4
#define DMI_READ_64U   *((DWORD64*)ptr_), ptr_ += 8
#define DMI_ENTRY_HEADER_SIZE   4

namespace smbios {
    Parser::Parser(char* data, size_t size, int version) : data_(data), size_(size),
        ptr_(nullptr), version_(version), entry_({ 0 }), ptrnext_(nullptr)
    {
        // is a valid version?
        if (version_ < SMBIOS_2_0) goto INVALID_DATA;
        reset();
        return;

    INVALID_DATA:
        DbgMsg("[SMBIOS] Invalid data: %p - 0x%x", data, version_);
        data_ = ptr_ = start_ = nullptr;
    }

    char* Parser::getString(int index) const
    {
        if (index <= 0) return (char*)"";

        char* ptr = (char*)start_ + (size_t)entry_.length - DMI_ENTRY_HEADER_SIZE;
        for (int i = 1; *ptr != 0 && i < index; ++i)
        {
            // TODO: check buffer limits
            while (*ptr != 0) ++ptr;
            ++ptr;
        }
        return ptr;
    }

    void Parser::reset()
    {
        ptr_ = start_ = nullptr;
    }

    Entry* Parser::next()
    {
        if (data_ == nullptr) return nullptr;

        // jump to the next field
        if (ptr_ == nullptr)
            ptr_ = start_ = data_;
        else
        {
            ptr_ = start_ + entry_.length - DMI_ENTRY_HEADER_SIZE;
            while (MmIsAddressValid(ptr_) && ptr_ < data_ + size_ - 1 && !(ptr_[0] == 0 && ptr_[1] == 0)) ++ptr_;
            ptr_ += 2;
            if (!MmIsAddressValid(ptr_) || ptr_ >= data_ + size_)
            {
                ptr_ = start_ = nullptr;
                return nullptr;
            }
        }

        memset(&entry_, 0, sizeof(entry_));

        // entry header
        entry_.type = DMI_READ_8U;
        entry_.length = DMI_READ_8U;
        entry_.handle = DMI_READ_16U;
        entry_.rawdata = ptr_ - 4;
        entry_.strings = (char*)entry_.rawdata + entry_.length;
        start_ = ptr_;

        if (entry_.type == 127)
        {
            reset();
            return nullptr;
        }

        return parseEntry();
    }

    Entry* Parser::parseEntry()
    {
        switch (entry_.type) {
        case TYPE_BIOS_INFO: {
            // 2.0+
            if (version_ >= SMBIOS_2_0)
            {
                entry_.data.bios.Vendor_ = DMI_READ_8U;
                entry_.data.bios.BIOSVersion_ = DMI_READ_8U;
                entry_.data.bios.BIOSStartingSegment = DMI_READ_16U;
                entry_.data.bios.BIOSReleaseDate_ = DMI_READ_8U;
                entry_.data.bios.BIOSROMSize = DMI_READ_8U;
                for (size_t i = 0; i < 8; ++i)
                    entry_.data.bios.BIOSCharacteristics[i] = DMI_READ_8U;

                entry_.data.bios.Vendor = getString(entry_.data.bios.Vendor_);
                entry_.data.bios.BIOSVersion = getString(entry_.data.bios.BIOSVersion_);
                entry_.data.bios.BIOSReleaseDate = getString(entry_.data.bios.BIOSReleaseDate_);
            }
            // 2.4+
            if (version_ >= SMBIOS_2_4)
            {
                entry_.data.bios.Extensionchar1 = DMI_READ_8U;
                entry_.data.bios.Extensionchar2 = DMI_READ_8U;
                entry_.data.bios.SystemBIOSMajorRelease = DMI_READ_8U;
                entry_.data.bios.SystemBIOSMinorRelease = DMI_READ_8U;
                entry_.data.bios.EmbeddedFirmwareMajorRelease = DMI_READ_8U;
                entry_.data.bios.EmbeddedFirmwareMinorRelease = DMI_READ_8U;
            }
            break;
        }
        case TYPE_SYSTEM_INFO: {
            // 2.0+
            if (version_ >= SMBIOS_2_0)
            {
                entry_.data.sysinfo.Manufacturer_ = DMI_READ_8U;
                entry_.data.sysinfo.ProductName_ = DMI_READ_8U;
                entry_.data.sysinfo.Version_ = DMI_READ_8U;
                entry_.data.sysinfo.SerialNumber_ = DMI_READ_8U;

                entry_.data.sysinfo.Manufacturer = getString(entry_.data.sysinfo.Manufacturer_);
                entry_.data.sysinfo.ProductName = getString(entry_.data.sysinfo.ProductName_);
                entry_.data.sysinfo.Version = getString(entry_.data.sysinfo.Version_);
                entry_.data.sysinfo.SerialNumber = getString(entry_.data.sysinfo.SerialNumber_);
            }
            // 2.1+
            if (version_ >= SMBIOS_2_1)
            {
                entry_.data.sysinfo.UUID = ptr_;
                ptr_ += 16;
                entry_.data.sysinfo.WakeupType = DMI_READ_8U;
            }
            // 2.4+
            if (version_ >= SMBIOS_2_4)
            {
                entry_.data.sysinfo.SKUNumber_ = DMI_READ_8U;
                entry_.data.sysinfo.Family_ = DMI_READ_8U;

                entry_.data.sysinfo.SKUNumber = getString(entry_.data.sysinfo.SKUNumber_);
                entry_.data.sysinfo.Family = getString(entry_.data.sysinfo.Family_);
            }
            break;
        }
        case TYPE_BASEBOARD_INFO: {
            if (version_ >= SMBIOS_2_0)
            {
                entry_.data.baseboard.Manufacturer_ = DMI_READ_8U;
                entry_.data.baseboard.Product_ = DMI_READ_8U;
                entry_.data.baseboard.Version_ = DMI_READ_8U;
                entry_.data.baseboard.SerialNumber_ = DMI_READ_8U;
                entry_.data.baseboard.AssetTag_ = DMI_READ_8U;
                entry_.data.baseboard.FeatureFlags = DMI_READ_8U;
                entry_.data.baseboard.LocationInChassis_ = DMI_READ_8U;
                entry_.data.baseboard.ChassisHandle = DMI_READ_16U;
                entry_.data.baseboard.BoardType = DMI_READ_8U;
                entry_.data.baseboard.NoOfContainedObjectHandles = DMI_READ_8U;
                entry_.data.baseboard.ContainedObjectHandles = (SHORT*)ptr_;
                ptr_ += entry_.data.baseboard.NoOfContainedObjectHandles * sizeof(SHORT);

                entry_.data.baseboard.Manufacturer = getString(entry_.data.baseboard.Manufacturer_);
                entry_.data.baseboard.Product = getString(entry_.data.baseboard.Product_);
                entry_.data.baseboard.Version = getString(entry_.data.baseboard.Version_);
                entry_.data.baseboard.SerialNumber = getString(entry_.data.baseboard.SerialNumber_);
                entry_.data.baseboard.AssetTag = getString(entry_.data.baseboard.AssetTag_);
                entry_.data.baseboard.LocationInChassis = getString(entry_.data.baseboard.LocationInChassis_);
            }

            return &entry_;
        }
        case TYPE_SYSTEM_ENCLOSURE: {
            // 2.0+
            if (version_ >= SMBIOS_2_0)
            {
                entry_.data.sysenclosure.Manufacturer_ = DMI_READ_8U;
                entry_.data.sysenclosure.Type = DMI_READ_8U;
                entry_.data.sysenclosure.Version_ = DMI_READ_8U;
                entry_.data.sysenclosure.SerialNumber_ = DMI_READ_8U;
                entry_.data.sysenclosure.AssetTag_ = DMI_READ_8U;

                entry_.data.sysenclosure.Manufacturer = getString(entry_.data.sysenclosure.Manufacturer_);
                entry_.data.sysenclosure.Version = getString(entry_.data.sysenclosure.Version_);
                entry_.data.sysenclosure.SerialNumber = getString(entry_.data.sysenclosure.SerialNumber_);
                entry_.data.sysenclosure.AssetTag = getString(entry_.data.sysenclosure.AssetTag_);
            }
            // 2.1+
            if (version_ >= SMBIOS_2_1)
            {
                entry_.data.sysenclosure.BootupState = DMI_READ_8U;
                entry_.data.sysenclosure.PowerSupplyState = DMI_READ_8U;
                entry_.data.sysenclosure.ThermalState = DMI_READ_8U;
                entry_.data.sysenclosure.SecurityStatus = DMI_READ_8U;
            }
            // 2.3+
            if (version_ >= SMBIOS_2_3)
            {
                entry_.data.sysenclosure.OEMdefined = DMI_READ_32U;
                entry_.data.sysenclosure.Height = DMI_READ_8U;
                entry_.data.sysenclosure.NumberOfPowerCords = DMI_READ_8U;
                entry_.data.sysenclosure.ContainedElementCount = DMI_READ_8U;
                entry_.data.sysenclosure.ContainedElementRecordLength = DMI_READ_8U;
                entry_.data.sysenclosure.ContainedElements = ptr_;
                ptr_ += entry_.data.sysenclosure.ContainedElementCount * entry_.data.sysenclosure.ContainedElementRecordLength;
            }
            // 2.7+
            if (version_ >= SMBIOS_2_7)
            {
                entry_.data.sysenclosure.SKUNumber_ = DMI_READ_8U;

                entry_.data.sysenclosure.SKUNumber = getString(entry_.data.sysenclosure.SKUNumber_);
            }
            break;
        }
        case TYPE_PROCESSOR_INFO: {
            // 2.0+
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.processor.SocketDesignation_ = DMI_READ_8U;
                entry_.data.processor.ProcessorType = DMI_READ_8U;
                entry_.data.processor.ProcessorFamily = DMI_READ_8U;
                entry_.data.processor.ProcessorManufacturer_ = DMI_READ_8U;
                for (int i = 0; i < 8; ++i)
                    entry_.data.processor.ProcessorID[i] = DMI_READ_8U;
                entry_.data.processor.ProcessorVersion_ = DMI_READ_8U;
                entry_.data.processor.Voltage = DMI_READ_8U;
                entry_.data.processor.ExternalClock = DMI_READ_16U;
                entry_.data.processor.MaxSpeed = DMI_READ_16U;
                entry_.data.processor.CurrentSpeed = DMI_READ_16U;
                entry_.data.processor.Status = DMI_READ_8U;
                entry_.data.processor.ProcessorUpgrade = DMI_READ_8U;

                entry_.data.processor.SocketDesignation = getString(entry_.data.processor.SocketDesignation_);
                entry_.data.processor.ProcessorManufacturer = getString(entry_.data.processor.ProcessorManufacturer_);
                entry_.data.processor.ProcessorVersion = getString(entry_.data.processor.ProcessorVersion_);
            }
            // 2.1+
            if (version_ >= smbios::SMBIOS_2_1)
            {
                entry_.data.processor.L1CacheHandle = DMI_READ_16U;
                entry_.data.processor.L2CacheHandle = DMI_READ_16U;
                entry_.data.processor.L3CacheHandle = DMI_READ_16U;
            }
            // 2.3+
            if (version_ >= smbios::SMBIOS_2_3)
            {
                entry_.data.processor.SerialNumber_ = DMI_READ_8U;
                entry_.data.processor.AssetTagNumber_ = DMI_READ_8U;
                entry_.data.processor.PartNumber_ = DMI_READ_8U;

                entry_.data.processor.SerialNumber = getString(entry_.data.processor.SerialNumber_);
                entry_.data.processor.AssetTagNumber = getString(entry_.data.processor.AssetTagNumber_);
                entry_.data.processor.PartNumber = getString(entry_.data.processor.PartNumber_);
            }
            // 2.5+
            if (version_ >= smbios::SMBIOS_2_5)
            {
                entry_.data.processor.CoreCount = DMI_READ_8U;
                entry_.data.processor.CoreEnabled = DMI_READ_8U;
                entry_.data.processor.ThreadCount = DMI_READ_8U;
                entry_.data.processor.ProcessorCharacteristics = DMI_READ_16U;
            }
            //2.6+
            if (version_ >= smbios::SMBIOS_2_6)
            {
                entry_.data.processor.ProcessorFamily2 = DMI_READ_16U;
            }
            //3.0+
            if (version_ >= smbios::SMBIOS_3_0)
            {
                entry_.data.processor.CoreCount2 = DMI_READ_16U;
                entry_.data.processor.CoreEnabled2 = DMI_READ_16U;
                entry_.data.processor.ThreadCount2 = DMI_READ_16U;
            }

            return &entry_;
        }
        case TYPE_SYSTEM_SLOT: {
            // 2.0+
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.sysslot.SlotDesignation_ = DMI_READ_8U;
                entry_.data.sysslot.SlotType = DMI_READ_8U;
                entry_.data.sysslot.SlotDataBusWidth = DMI_READ_8U;
                entry_.data.sysslot.CurrentUsage = DMI_READ_8U;
                entry_.data.sysslot.SlotLength = DMI_READ_8U;
                entry_.data.sysslot.SlotID = DMI_READ_16U;
                entry_.data.sysslot.SlotCharacteristics1 = DMI_READ_8U;

                entry_.data.sysslot.SlotDesignation = getString(entry_.data.sysslot.SlotDesignation_);
            }
            // 2.1+
            if (version_ >= smbios::SMBIOS_2_1)
            {
                entry_.data.sysslot.SlotCharacteristics2 = DMI_READ_8U;
            }
            // 2.6+
            if (version_ >= smbios::SMBIOS_2_6)
            {
                entry_.data.sysslot.SegmentGroupNumber = DMI_READ_16U;
                entry_.data.sysslot.BusNumber = DMI_READ_8U;
                entry_.data.sysslot.DeviceOrFunctionNumber = DMI_READ_8U;
            }
            break;
        }
        case TYPE_PHYSICAL_MEMORY_ARRAY: {
            // 2.1+
            if (version_ >= smbios::SMBIOS_2_1)
            {
                entry_.data.physmem.Location = DMI_READ_8U;
                entry_.data.physmem.Use = DMI_READ_8U;
                entry_.data.physmem.ErrorCorrection = DMI_READ_8U;
                entry_.data.physmem.MaximumCapacity = DMI_READ_32U;
                entry_.data.physmem.ErrorInformationHandle = DMI_READ_16U;
                entry_.data.physmem.NumberDevices = DMI_READ_16U;
            }
            // 2.7+
            if (version_ >= smbios::SMBIOS_2_7)
            {
                entry_.data.physmem.ExtendedMaximumCapacity = DMI_READ_64U;
            }
            break;
        }
        case TYPE_MEMORY_DEVICE: {
            // 2.1+
            if (version_ >= smbios::SMBIOS_2_1)
            {
                entry_.data.memory.PhysicalArrayHandle = DMI_READ_16U;
                entry_.data.memory.ErrorInformationHandle = DMI_READ_16U;
                entry_.data.memory.TotalWidth = DMI_READ_16U;
                entry_.data.memory.DataWidth = DMI_READ_16U;
                entry_.data.memory.Size = DMI_READ_16U;
                entry_.data.memory.FormFactor = DMI_READ_8U;
                entry_.data.memory.DeviceSet = DMI_READ_8U;
                entry_.data.memory.DeviceLocator_ = DMI_READ_8U;
                entry_.data.memory.BankLocator_ = DMI_READ_8U;
                entry_.data.memory.MemoryType = DMI_READ_8U;
                entry_.data.memory.TypeDetail = DMI_READ_16U;

                entry_.data.memory.DeviceLocator = getString(entry_.data.memory.DeviceLocator_);
                entry_.data.memory.BankLocator = getString(entry_.data.memory.BankLocator_);
            }
            // 2.3+
            if (version_ >= smbios::SMBIOS_2_3)
            {
                entry_.data.memory.Speed = DMI_READ_16U;
                entry_.data.memory.Manufacturer_ = DMI_READ_8U;
                entry_.data.memory.SerialNumber_ = DMI_READ_8U;
                entry_.data.memory.AssetTagNumber_ = DMI_READ_8U;
                entry_.data.memory.PartNumber_ = DMI_READ_8U;

                entry_.data.memory.Manufacturer = getString(entry_.data.memory.Manufacturer_);
                entry_.data.memory.SerialNumber = getString(entry_.data.memory.SerialNumber_);
                entry_.data.memory.AssetTagNumber = getString(entry_.data.memory.AssetTagNumber_);
                entry_.data.memory.PartNumber = getString(entry_.data.memory.PartNumber_);
            }
            // 2.6+
            if (version_ >= smbios::SMBIOS_2_6)
            {
                entry_.data.memory.Attributes = DMI_READ_8U;
            }
            // 2.7+
            if (version_ >= smbios::SMBIOS_2_7)
            {
                entry_.data.memory.ExtendedSize = DMI_READ_32U;
                entry_.data.memory.ConfiguredClockSpeed = DMI_READ_16U;
            }
            // 2.8+
            if (version_ >= smbios::SMBIOS_2_8)
            {
                entry_.data.memory.MinimumVoltage = DMI_READ_16U;
                entry_.data.memory.MaximumVoltage = DMI_READ_16U;
                entry_.data.memory.ConfiguredVoltage = DMI_READ_16U;
            }
            break;
        }
        case TYPE_OEM_STRINGS: {
            // 2.0+
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.oemstrings.Count = DMI_READ_8U;
                entry_.data.oemstrings.Values = (char*)ptr_;
            }
            break;
        }
        case TYPE_PORT_CONNECTOR: {
            // 2.0+
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.portconn.InternalReferenceDesignator_ = DMI_READ_8U;
                entry_.data.portconn.InternalConnectorType = DMI_READ_8U;
                entry_.data.portconn.ExternalReferenceDesignator_ = DMI_READ_8U;
                entry_.data.portconn.ExternalConnectorType = DMI_READ_8U;
                entry_.data.portconn.PortType = DMI_READ_8U;

                entry_.data.portconn.ExternalReferenceDesignator = getString(entry_.data.portconn.ExternalReferenceDesignator_);
                entry_.data.portconn.InternalReferenceDesignator = getString(entry_.data.portconn.InternalReferenceDesignator_);
            }
            break;
        }
        case TYPE_MEMORY_ARRAY_MAPPED_ADDRESS: {
            if (version_ >= smbios::SMBIOS_2_1)
            {
                entry_.data.mamaddr.StartingAddress = DMI_READ_32U;
                entry_.data.mamaddr.EndingAddress = DMI_READ_32U;
                entry_.data.mamaddr.MemoryArrayHandle = DMI_READ_16U;
                entry_.data.mamaddr.PartitionWidth = DMI_READ_8U;
            }
            if (version_ >= smbios::SMBIOS_2_7)
            {
                entry_.data.mamaddr.ExtendedStartingAddress = DMI_READ_64U;
                entry_.data.mamaddr.ExtendedEndingAddress = DMI_READ_64U;
            }
            break;
        }
        case TYPE_MEMORY_DEVICE_MAPPED_ADDRESS: {
            if (version_ >= smbios::SMBIOS_2_1)
            {
                entry_.data.mdmaddr.StartingAddress = DMI_READ_32U;
                entry_.data.mdmaddr.EndingAddress = DMI_READ_32U;
                entry_.data.mdmaddr.MemoryDeviceHandle = DMI_READ_16U;
                entry_.data.mdmaddr.MemoryArrayMappedAddressHandle = DMI_READ_16U;
                entry_.data.mdmaddr.PartitionRowPosition = DMI_READ_8U;
                entry_.data.mdmaddr.InterleavePosition = DMI_READ_8U;
                entry_.data.mdmaddr.InterleavedDataDepth = DMI_READ_8U;
            }
            if (version_ >= smbios::SMBIOS_2_7)
            {
                entry_.data.mdmaddr.ExtendedStartingAddress = DMI_READ_64U;
                entry_.data.mdmaddr.ExtendedEndingAddress = DMI_READ_64U;
            }
            break;
        }
        case TYPE_SYSTEM_BOOT_INFO: {
            if (version_ >= smbios::SMBIOS_2_0)
            {
                ptr_ += sizeof(entry_.data.bootinfo.Reserved);
                entry_.data.bootinfo.BootStatus = ptr_;
            }
            break;
        }
        case TYPE_MANAGEMENT_DEVICE: {
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.mdev.Description_ = DMI_READ_8U;
                entry_.data.mdev.Type = DMI_READ_8U;
                entry_.data.mdev.Address = DMI_READ_32U;
                entry_.data.mdev.AddressType = DMI_READ_8U;

                entry_.data.mdev.Description = getString(entry_.data.mdev.Description_);
            }
            break;
        }
        case TYPE_MANAGEMENT_DEVICE_COMPONENT: {
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.mdcom.Description_ = DMI_READ_8U;
                entry_.data.mdcom.ManagementDeviceHandle = DMI_READ_16U;
                entry_.data.mdcom.ComponentHandle = DMI_READ_16U;
                entry_.data.mdcom.ThresholdHandle = DMI_READ_16U;

                entry_.data.mdev.Description = getString(entry_.data.mdev.Description_);
            }
            break;
        }
        case TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA: {
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.mdtdata.LowerThresholdNonCritical = DMI_READ_16U;
                entry_.data.mdtdata.UpperThresholdNonCritical = DMI_READ_16U;
                entry_.data.mdtdata.LowerThresholdCritical = DMI_READ_16U;
                entry_.data.mdtdata.UpperThresholdCritical = DMI_READ_16U;
                entry_.data.mdtdata.LowerThresholdNonRecoverable = DMI_READ_16U;
                entry_.data.mdtdata.UpperThresholdNonRecoverable = DMI_READ_16U;
            }
            break;
        }
        case TYPE_ONBOARD_DEVICES_EXTENDED_INFO: {
            if (version_ >= smbios::SMBIOS_2_0)
            {
                entry_.data.odeinfo.ReferenceDesignation_ = DMI_READ_8U;
                entry_.data.odeinfo.DeviceType = DMI_READ_8U;
                entry_.data.odeinfo.DeviceTypeInstance = DMI_READ_8U;
                entry_.data.odeinfo.SegmentGroupNumber = DMI_READ_16U;
                entry_.data.odeinfo.BusNumber = DMI_READ_8U;
                entry_.data.odeinfo.DeviceOrFunctionNumber = DMI_READ_8U;

                entry_.data.odeinfo.ReferenceDesignation = getString(entry_.data.odeinfo.ReferenceDesignation_);
            }
            break;
        }
        default: {
            break;
        }
        }

        return &entry_;
    }

    int Parser::version() const
    {
        return version_;
    }

    bool Parser::valid() const
    {
        return data_ != nullptr;
    }

}
