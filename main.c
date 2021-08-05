/*
Author: Bobby Cooke @0xBoku | https://github.com/boku7 | https://0xBoku.com | https://www.linkedin.com/in/bobby-cooke/
Credits / References: Pavel Yosifovich (@zodiacon),Reenz0h from @SEKTOR7net, @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique)
*/
#include <Windows.h>
#include "bcookesHellsGate.h"
#include <stdio.h>

extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

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
PVOID ntdll = NULL;
PVOID ntdllExportTable = NULL;
PVOID ntdllExAddrTbl = NULL;
PVOID ntdllExNamePtrTbl = NULL;
PVOID ntdllExOrdinalTbl = NULL;
PVOID ntQrySysInfoAddr = NULL;
const char ntQrySysInfoStr[] = "NtQuerySystemInformation";
DWORD ntQrySysInfoStrLen = 0;
DWORD  ntQrySysInfoSyscallNumber = 0;
const char ntAllocVMStr[] = "NtAllocateVirtualMemory";
DWORD ntAllocVMStrLen = 0;
PVOID ntAllocVMAddr = NULL;
DWORD ntAllocVMSyscallNumber = 0;


void main() {
	// Use Position Independent Shellcode to resolve the address of NTDLL and its export tables
	ntdll = getntdll();
	printf("%p : NTDLL Base Address\r\n", ntdll);
	ntdllExportTable = getExportTable(ntdll);
	printf("%p : NTDLL Export Table Address\r\n", ntdllExportTable);
	ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdll);
	printf("%p : NTDLL Export Address Table Address\r\n", ntdllExAddrTbl);
	ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdll);
	printf("%p : NTDLL Export Name Pointer Table Address\r\n", ntdllExNamePtrTbl);
	ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdll);
	printf("%p : NTDLL Export Ordinal Table Address\r\n", ntdllExOrdinalTbl);
	// Find the address of NTDLL.NtQuerySystemInformation by looping through NTDLL export tables
	ntQrySysInfoStrLen = sizeof(ntQrySysInfoStr);
	printf("Looping through NTDLL Export tables to discover the address for NTDLL.%s..\r\n", ntQrySysInfoStr);
	ntQrySysInfoAddr = getApiAddr(
		ntQrySysInfoStrLen,
		ntQrySysInfoStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	printf("%p : NTDLL.%s Address\r\n", ntQrySysInfoAddr, ntQrySysInfoStr);
	ntQrySysInfoSyscallNumber = findSyscallNumber(ntQrySysInfoAddr);
	if (ntQrySysInfoSyscallNumber == 0) {
		printf("Failed to discover the syscall number for %s. The API is likely hooked by EDR. Exiting program now.\r\n", ntQrySysInfoStr);
		return;
	}
	printf("%x : Syscall number for NTDLL.%s\r\n", ntQrySysInfoSyscallNumber, ntQrySysInfoStr);

	// Find the address of NTDLL.NtAllocateVirtualMemory by looping through NTDLL export tables
	ntAllocVMStrLen = sizeof(ntAllocVMStr);
	ntAllocVMAddr = getApiAddr(
		ntAllocVMStrLen,
		ntAllocVMStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	printf("%p : NTDLL.%s Address\r\n", ntAllocVMAddr, ntAllocVMStr);
	ntAllocVMSyscallNumber = findSyscallNumber(ntAllocVMAddr);
	if (ntAllocVMSyscallNumber == 0) {
		printf("Failed to discover the syscall number for %s. The API is likely hooked by EDR. Exiting program now.\r\n", ntAllocVMStr);
		return;
	}
	printf("%x : Syscall number for NTDLL.%s\r\n", ntAllocVMSyscallNumber, ntAllocVMStr);

	// Allocate the buffer for the process information returned from NtQuerySystemInformation
	ULONG size = 1 << 18;
	PVOID base_addr = NULL;
	SIZE_T buffSize1 = (SIZE_T)size;
	ULONG required = 0;

	// NtAllocateVirtualMemory
	HellsGate(ntAllocVMSyscallNumber);
	HellDescent((HANDLE)-1, &base_addr, 0, &buffSize1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// NtQuerySystemInformation
	HellsGate(ntQrySysInfoSyscallNumber);
	NTSTATUS status = HellDescent(SystemProcessInformation, base_addr, size, &required);
	if (status == STATUS_BUFFER_TOO_SMALL) {
		size = required + (1 << 14);
		SIZE_T buffSize2 = size;
		// NtAllocateVirtualMemory
		HellsGate(ntAllocVMSyscallNumber);
		HellDescent((HANDLE)-1, &base_addr, 0, &buffSize2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	NTSTATUS status2 = HellDescent(SystemProcessInformation, base_addr, size, &required);
	SYSTEM_PROCESS_INFORMATION * procinfo = (SYSTEM_PROCESS_INFORMATION*)base_addr;
	while (TRUE) {
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
