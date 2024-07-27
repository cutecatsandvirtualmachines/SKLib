#pragma once

#include "cpp.h"
#include "StringEx.h"

#define SMBIOS_STRING(name)  char name##_; char * name

namespace smbios {

	static const int TYPE_BIOS_INFO = 0;
	struct BiosInfo
	{
		SMBIOS_STRING(Vendor);
		SMBIOS_STRING(BIOSVersion);
		SHORT BIOSStartingSegment;
		SMBIOS_STRING(BIOSReleaseDate);
		char BIOSROMSize;
		char BIOSCharacteristics[8];
		char Extensionchar1;
		char Extensionchar2;
		char SystemBIOSMajorRelease;
		char SystemBIOSMinorRelease;
		char EmbeddedFirmwareMajorRelease;
		char EmbeddedFirmwareMinorRelease;
	};

	const static int TYPE_SYSTEM_INFO = 1;
	struct SystemInfo
	{
		// 2.0+
		SMBIOS_STRING(Manufacturer);
		SMBIOS_STRING(ProductName);
		SMBIOS_STRING(Version);
		SMBIOS_STRING(SerialNumber);
		// 2.1+
		char* UUID;
		char WakeupType;
		// 2.4+
		SMBIOS_STRING(SKUNumber);
		SMBIOS_STRING(Family);
	};

	const static int TYPE_BASEBOARD_INFO = 2;
	struct BaseboardInfo
	{
		// 2.0+
		SMBIOS_STRING(Manufacturer);
		SMBIOS_STRING(Product);
		SMBIOS_STRING(Version);
		SMBIOS_STRING(SerialNumber);
		SMBIOS_STRING(AssetTag);
		char FeatureFlags;
		SMBIOS_STRING(LocationInChassis);
		SHORT ChassisHandle;
		char BoardType;
		char NoOfContainedObjectHandles;
		SHORT* ContainedObjectHandles;
	};

	const static int TYPE_SYSTEM_ENCLOSURE = 3;
	struct SystemEnclosure
	{
		// 2.0+
		SMBIOS_STRING(Manufacturer);
		char Type;
		SMBIOS_STRING(Version);
		SMBIOS_STRING(SerialNumber);
		SMBIOS_STRING(AssetTag);
		// 2.1+
		char BootupState;
		char PowerSupplyState;
		char ThermalState;
		char SecurityStatus;
		// 2.3+
		DWORD32 OEMdefined;
		char Height;
		char NumberOfPowerCords;
		char ContainedElementCount;
		char ContainedElementRecordLength;
		char* ContainedElements;
		// 2.7+
		SMBIOS_STRING(SKUNumber);
	};

	const static int TYPE_PROCESSOR_INFO = 4;
	struct ProcessorInfo
	{
		// 2.0+
		SMBIOS_STRING(SocketDesignation);
		char ProcessorType;
		char ProcessorFamily;
		SMBIOS_STRING(ProcessorManufacturer);
		char ProcessorID[8];
		SMBIOS_STRING(ProcessorVersion);
		char Voltage;
		SHORT ExternalClock;
		SHORT MaxSpeed;
		SHORT CurrentSpeed;
		char Status;
		char ProcessorUpgrade;
		// 2.1+
		SHORT L1CacheHandle;
		SHORT L2CacheHandle;
		SHORT L3CacheHandle;
		// 2.3+
		SMBIOS_STRING(SerialNumber);
		SMBIOS_STRING(AssetTagNumber);
		SMBIOS_STRING(PartNumber);
		// 2.5+
		char CoreCount;
		char CoreEnabled;
		char ThreadCount;
		SHORT ProcessorCharacteristics;
		// 2.6+
		SHORT ProcessorFamily2;
		// 3.0+
		SHORT CoreCount2;
		SHORT CoreEnabled2;
		SHORT ThreadCount2;
	};

	const static int TYPE_PORT_CONNECTOR = 8;
	struct PortConnector
	{
		SMBIOS_STRING(InternalReferenceDesignator);
		char InternalConnectorType;
		SMBIOS_STRING(ExternalReferenceDesignator);
		char ExternalConnectorType;
		char PortType;
	};

	const static int TYPE_SYSTEM_SLOT = 9;
	struct SystemSlot
	{
		// 2.0+
		SMBIOS_STRING(SlotDesignation);
		char SlotType;
		char SlotDataBusWidth;
		char CurrentUsage;
		char SlotLength;
		SHORT SlotID;
		char SlotCharacteristics1;
		// 2.1+
		char SlotCharacteristics2;
		// 2.6+
		SHORT SegmentGroupNumber;
		char BusNumber;
		char DeviceOrFunctionNumber;
	};

	const static int TYPE_OEM_STRINGS = 11;
	struct OemStrings
	{
		// 2.0+
		char Count;
		char* Values;
	};

	const static int TYPE_PHYSICAL_MEMORY_ARRAY = 16;
	struct PhysicalMemoryArray
	{
		// 2.1+
		char Location;
		char Use;
		char ErrorCorrection;
		DWORD32 MaximumCapacity;
		SHORT ErrorInformationHandle;
		SHORT NumberDevices;
		// 2.7+
		DWORD64 ExtendedMaximumCapacity;
	};

	const static int TYPE_MEMORY_DEVICE = 17;
	struct MemoryDevice
	{
		// 2.1+
		SHORT PhysicalArrayHandle;
		SHORT ErrorInformationHandle;
		SHORT TotalWidth;
		SHORT DataWidth;
		SHORT Size;
		char FormFactor;
		char DeviceSet;
		SMBIOS_STRING(DeviceLocator);
		SMBIOS_STRING(BankLocator);
		char MemoryType;
		SHORT TypeDetail;
		// 2.3+
		SHORT Speed;
		SMBIOS_STRING(Manufacturer);
		SMBIOS_STRING(SerialNumber);
		SMBIOS_STRING(AssetTagNumber);
		SMBIOS_STRING(PartNumber);
		// 2.6+
		char Attributes;
		// 2.7+
		DWORD32 ExtendedSize;
		SHORT ConfiguredClockSpeed;
		// 2.8+
		SHORT MinimumVoltage;
		SHORT MaximumVoltage;
		SHORT ConfiguredVoltage;
	};

	const static int TYPE_MEMORY_ARRAY_MAPPED_ADDRESS = 19;
	struct MemoryArrayMappedAddress
	{
		// 2.1+
		DWORD32 StartingAddress;
		DWORD32 EndingAddress;
		SHORT MemoryArrayHandle;
		char PartitionWidth;
		// 2.7+
		DWORD64 ExtendedStartingAddress;
		DWORD64 ExtendedEndingAddress;
	};

	const static int TYPE_MEMORY_DEVICE_MAPPED_ADDRESS = 20;
	struct MemoryDeviceMappedAddress
	{
		// 2.1+
		DWORD32 StartingAddress;
		DWORD32 EndingAddress;
		SHORT MemoryDeviceHandle;
		SHORT MemoryArrayMappedAddressHandle;
		char PartitionRowPosition;
		char InterleavePosition;
		char InterleavedDataDepth;
		// 2.7+
		DWORD64 ExtendedStartingAddress;
		DWORD64 ExtendedEndingAddress;
	};

	const static int TYPE_SYSTEM_BOOT_INFO = 32;
	struct SystemBootInfo
	{
		// 2.0+
		char Reserved[6];
		char* BootStatus;
	};

	const static int TYPE_MANAGEMENT_DEVICE = 34;
	struct ManagementDevice
	{
		// 2.0+
		SMBIOS_STRING(Description);
		char Type;
		DWORD32 Address;
		char AddressType;
	};

	const static int TYPE_MANAGEMENT_DEVICE_COMPONENT = 35;
	struct ManagementDeviceComponent
	{
		// 2.0+
		SMBIOS_STRING(Description);
		SHORT ManagementDeviceHandle;
		SHORT ComponentHandle;
		SHORT ThresholdHandle;
	};

	const static int TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA = 36;
	struct ManagementDeviceThresholdData
	{
		// 2.0+
		SHORT LowerThresholdNonCritical;
		SHORT UpperThresholdNonCritical;
		SHORT LowerThresholdCritical;
		SHORT UpperThresholdCritical;
		SHORT LowerThresholdNonRecoverable;
		SHORT UpperThresholdNonRecoverable;
	};

	const static int TYPE_ONBOARD_DEVICES_EXTENDED_INFO = 41;
	struct OnboardDevicesExtendedInfo
	{
		// 2.0+
		SMBIOS_STRING(ReferenceDesignation);
		char DeviceType;
		char DeviceTypeInstance;
		SHORT SegmentGroupNumber;
		char BusNumber;
		char DeviceOrFunctionNumber;
	};

	struct Entry
	{
		char type;
		char length;
		SHORT handle;
		union
		{
			ProcessorInfo processor;
			BaseboardInfo baseboard;
			SystemInfo sysinfo;
			BiosInfo bios;
			SystemEnclosure sysenclosure;
			PhysicalMemoryArray physmem;
			MemoryDevice memory;
			SystemSlot sysslot;
			OemStrings oemstrings;
			PortConnector portconn;
			MemoryArrayMappedAddress mamaddr;
			MemoryDeviceMappedAddress mdmaddr;
			SystemBootInfo bootinfo;
			ManagementDevice mdev;
			ManagementDeviceComponent mdcom;
			ManagementDeviceThresholdData mdtdata;
			OnboardDevicesExtendedInfo odeinfo;
		} data;
		char* rawdata;
		char* strings;
	};

	enum SpecVersion
	{
		SMBIOS_2_0 = 0x0200,
		SMBIOS_2_1 = 0x0201,
		SMBIOS_2_2 = 0x0202,
		SMBIOS_2_3 = 0x0203,
		SMBIOS_2_4 = 0x0204,
		SMBIOS_2_5 = 0x0205,
		SMBIOS_2_6 = 0x0206,
		SMBIOS_2_7 = 0x0207,
		SMBIOS_2_8 = 0x0208,
		SMBIOS_3_0 = 0x0300,
		SMBIOS_3_1 = 0x0301,
		SMBIOS_3_2 = 0x0302,
		SMBIOS_3_3 = 0x0303,
		SMBIOS_3_4 = 0x0304
	};

	struct RawSMBIOSData
	{
		char    Used20CallingMethod;
		char    SMBIOSMajorVersion;
		char    SMBIOSMinorVersion;
		char    DmiRevision;
		DWORD32   Length;
		char    SMBIOSTableData[1];
	};

	class Parser
	{
	public:
		Parser(char* data, size_t size, int version);
		void reset();
		Entry* next();
		int version() const;
		bool valid() const;

	private:
		char* data_;
		size_t size_;
		Entry entry_;
		char* ptr_;
		char* ptrnext_;
		char* start_;
		int version_;

		Entry* parseEntry();
		char* getString(int index) const;
	};
}

#undef SMBIOS_STRING

