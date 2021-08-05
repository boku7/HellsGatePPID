#include <windows.h>
#include "bcookesHellsGate.h"
#include <stdio.h>

EXTERN_C NTSTATUS testfunc(
	IN DWORD var1,
	IN DWORD var2
);

EXTERN_C PVOID getntdll();

EXTERN_C PVOID getExportTable(
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExAddressTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExNamePointerTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExOrdinalTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getApiAddr(
	IN DWORD apiNameStringLen,
	IN LPSTR apiNameString,
	IN PVOID moduleAddr,
	IN PVOID ExExAddressTable,
	IN PVOID ExNamePointerTable,
	IN PVOID ExOrdinalTable
);

EXTERN_C DWORD findSyscallNumber(
	IN PVOID ntdllApiAddr
);

EXTERN_C DWORD compExplorer(
	IN PVOID explorerWString
);

EXTERN_C VOID HellsGate(WORD wSystemCall);

EXTERN_C NTSTATUS HellDescent1(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

EXTERN_C NTSTATUS HellDescent2(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

void main() {
	// Use Position Independent Shellcode to resolve the address of NTDLL and its export tables
	PVOID ntdll = getntdll();
	printf("%p : NTDLL Base Address\r\n", ntdll);
	PVOID ntdllExportTable = getExportTable(ntdll);
	printf("%p : NTDLL Export Table Address\r\n", ntdllExportTable);
	PVOID ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdll);
	printf("%p : NTDLL Export Address Table Address\r\n", ntdllExAddrTbl);
	PVOID ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdll);
	printf("%p : NTDLL Export Name Pointer Table Address\r\n", ntdllExNamePtrTbl);
	PVOID ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdll);
	printf("%p : NTDLL Export Ordinal Table Address\r\n", ntdllExOrdinalTbl);
	// Find the address of NTDLL.NtQuerySystemInformation by looping through NTDLL export tables
	char ntQrySysInfoStr[] = "NtQuerySystemInformation";
	DWORD ntQrySysInfoStrLen = sizeof(ntQrySysInfoStr);
	printf("Looping through NTDLL Export tables to discover the address for NTDLL.%s..\r\n", ntQrySysInfoStr);
	PVOID ntQrySysInfoAddr = getApiAddr(
		ntQrySysInfoStrLen,
		ntQrySysInfoStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	printf("%p : NTDLL.%s Address\r\n", ntQrySysInfoAddr, ntQrySysInfoStr);
	DWORD  ntQrySysInfoSyscallNumber = findSyscallNumber(ntQrySysInfoAddr);
	if (ntQrySysInfoSyscallNumber == 0) {
		printf("Failed to discover the syscall number for %s. The API is likely hooked by EDR. Exiting program now.\r\n", ntQrySysInfoStr);
		return;
	}
	printf("%x : Syscall number for NTDLL.%s\r\n", ntQrySysInfoSyscallNumber, ntQrySysInfoStr);

	// Find the address of NTDLL.NtAllocateVirtualMemory by looping through NTDLL export tables
	char ntAllocVMStr[] = "NtAllocateVirtualMemory";
	DWORD ntAllocVMStrLen = sizeof(ntAllocVMStr);
	PVOID ntAllocVMAddr = getApiAddr(
		ntAllocVMStrLen,
		ntAllocVMStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	printf("%p : NTDLL.%s Address\r\n", ntAllocVMAddr, ntAllocVMStr);
	DWORD ntAllocVMSyscallNumber = findSyscallNumber(ntAllocVMAddr);
	if (ntAllocVMSyscallNumber == 0) {
		printf("Failed to discover the syscall number for %s. The API is likely hooked by EDR. Exiting program now.\r\n", ntAllocVMStr);
		return;
	}
	printf("%x : Syscall number for NTDLL.%s\r\n", ntAllocVMSyscallNumber, ntAllocVMStr);

	// Allocate the buffer for the process information returned from NtQuerySystemInformation
	ULONG size = 1 << 18;
	PVOID base_addr = NULL;
	SIZE_T buffSize1 = size;
	ULONG required;

	HellsGate(ntAllocVMSyscallNumber);
	HellDescent2((HANDLE)-1, &base_addr, 0, &buffSize1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	HellsGate(ntQrySysInfoSyscallNumber);
	NTSTATUS status = HellDescent1(SystemProcessInformation, base_addr, size, &required);
	if (status == STATUS_BUFFER_TOO_SMALL) {
		size = required + (1 << 14);
		SIZE_T buffSize2 = size;
		HellsGate(ntAllocVMSyscallNumber);
		HellDescent2((HANDLE)-1, &base_addr, 0, &buffSize2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	HellDescent1(SystemProcessInformation, base_addr, size, &required);
	auto procinfo = (SYSTEM_PROCESS_INFORMATION*)base_addr;
	while (true) {
		BOOL check = compExplorer(procinfo->ImageName.Buffer);
		if (check == 1) {
			printf("%ws | PID: %6u | PPID: %6u\n",
				procinfo->ImageName.Buffer,
				HandleToULong(procinfo->UniqueProcessId),
				HandleToULong(procinfo->InheritedFromUniqueProcessId)
			);
			break;
		}
		procinfo = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)procinfo + procinfo->NextEntryOffset);
	}
	return;
}

