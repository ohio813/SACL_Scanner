#include <windows.h>
#include <dsgetdc.h>
#include <lm.h>
#include <aclapi.h>
#include <Sddl.h>
#include <stdio.h>
#include <tchar.h>
#include <activeds.h>
#include <objbase.h>
#include <initguid.h>
#include "guid_lookup.h"


#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ActiveDS.lib")
#pragma comment(lib, "ADSIid.Lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Oleaut32.lib")
#pragma comment(lib, "Netapi32.lib")

BOOL EnablePrivilege(LPCWSTR privilegeName) {
	HANDLE hToken;  // Process token handle
	TOKEN_PRIVILEGES tp;  // Token privileges structure
	LUID luid;  // Locally unique identifier for the privilege

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {  // Open the process token
		wprintf(L"Failed to open process token. Error: %lu\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {  // Lookup the privilege value
		wprintf(L"Failed to lookup privilege value. Error: %lu\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;  // Set the privilege count to 1
	tp.Privileges[0].Luid = luid;  // Set the LUID
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  // Enable the privilege

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {  // Adjust the token privileges
		wprintf(L"Failed to adjust token privileges. Error: %lu\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {  // Check if the privilege is assigned
		wprintf(L"The token does not have the specified privilege. Error: %lu\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

// Define specific access rights for reading and writing properties
#define RIGHT_DS_READ_PROPERTY   0x10
#define RIGHT_DS_WRITE_PROPERTY  0x20

// Function to print a hex dump of a buffer
void PrintHexDump(const void* data, size_t size) {
	const unsigned char* byteData = (const unsigned char*)data;
	for (size_t i = 0; i < size; i++) {
		printf("%02X ", byteData[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n");
}

// Function to calculate the SID start based on the flags in a SYSTEM_AUDIT_OBJECT_ACE
PSID CalculateSidStart(SYSTEM_AUDIT_OBJECT_ACE* pAuditObjectAce) {
	if (pAuditObjectAce->Flags == 0) {
		// No flags set
		return (PSID)((BYTE*)&pAuditObjectAce->ObjectType + sizeof(GUID));  // Default to ObjectType
	}
	else if ((pAuditObjectAce->Flags & ACE_OBJECT_TYPE_PRESENT) && (pAuditObjectAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)) {  // Both flags set
		// Both ACE_OBJECT_TYPE_PRESENT and ACE_INHERITED_OBJECT_TYPE_PRESENT are set
		return (PSID)((BYTE*)&pAuditObjectAce->InheritedObjectType + sizeof(GUID));
	}
	else if (pAuditObjectAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
		// Only ACE_OBJECT_TYPE_PRESENT is set
		return (PSID)((BYTE*)&pAuditObjectAce->ObjectType + sizeof(GUID));
	}
	else if (pAuditObjectAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
		// Only ACE_INHERITED_OBJECT_TYPE_PRESENT is set
		return (PSID)((BYTE*)&pAuditObjectAce->InheritedObjectType + sizeof(GUID));
	}
	return NULL; // Return NULL if no valid conditions are met
}

// Function to verify the SID structure
void VerifySidStructure(PSID pSid, BOOL verbose) {
	if (!IsValidSid(pSid)) {  // Check if the SID is valid
		printf("Invalid SID structure detected.\n");
	}
	else if (verbose) {  // Print the SID structure if verbose flag is set
		printf("SID is valid. Details:\n");
		PrintHexDump(pSid, GetLengthSid(pSid));
	}
}

// Function to retrieve the domain controller name
BOOL GetDomainControllerName(WCHAR* domainController, DWORD size) {
	PDOMAIN_CONTROLLER_INFO pDcInfo;  // Domain controller information
	DWORD result = DsGetDcName(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pDcInfo);  // Get the domain controller name
	if (result == NO_ERROR) {  // Check if the domain controller name was retrieved successfully
		// Copy the domain controller name to the output buffer
		wcsncpy_s(domainController, size, pDcInfo->DomainControllerName + 2, size - 1); // +2 skips "\\" prefix
		NetApiBufferFree(pDcInfo); // Free the domain controller information buffer
		return TRUE;
	}
	else {
		wprintf(L"Failed to retrieve domain controller name. Error: %lu\n", result);
		return FALSE;
	}
}

// Function to resolve a SID to a user or group name
void ResolveSidWithFallback(PSID pSid) {
	WCHAR name[256];
	WCHAR domain[256];
	WCHAR domainController[256];
	DWORD nameSize = sizeof(name) / sizeof(WCHAR);
	DWORD domainSize = sizeof(domain) / sizeof(WCHAR);
	SID_NAME_USE sidType;

	// Get the domain controller name
	if (GetDomainControllerName(domainController, sizeof(domainController) / sizeof(WCHAR))) {
		// Try resolving with the retrieved domain controller
		if (LookupAccountSid(domainController, pSid, name, &nameSize, domain, &domainSize, &sidType)) {
			wprintf(L"User/Group: %s\\%s\n", domain, name);
		}
		else {
			// Fallback to using SDDL if LookupAccountSid fails
			LPWSTR sddlSid;
			if (ConvertSidToStringSidW(pSid, &sddlSid)) {
				wprintf(L"Unable to lookup SID. SDDL: %s\n", sddlSid);
				LocalFree(sddlSid);
			}
			else {
				wprintf(L"Failed to convert SID to SDDL.\n");
			}
		}
	}
	else {
		wprintf(L"Domain controller not found; cannot resolve domain SID.\n");
	}
}

void ProcessGUIDFromAce(const GUID* objectType, DWORD accessMask, BOOL verbose) {
	if (verbose) {
		printf("Debug: Looking up GUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
			objectType->Data1, objectType->Data2, objectType->Data3,
			objectType->Data4[0], objectType->Data4[1], objectType->Data4[2], objectType->Data4[3],
			objectType->Data4[4], objectType->Data4[5], objectType->Data4[6], objectType->Data4[7]);
	}

	struct GuidLookup* entry = in_word_set(objectType);
	if (entry) {
		wprintf(L"  Auditing: %hs\n", entry->name);
		if (accessMask & RIGHT_DS_READ_PROPERTY) {
			wprintf(L"    Auditing Read Access\n");
		}
		if (accessMask & RIGHT_DS_WRITE_PROPERTY) {
			wprintf(L"    Auditing Write Access\n");
		}
	}
	else {
		printf("  Unknown GUID: %08x-%04x-%04x-%02x%02x-%02x%02x-%02x%02x%02x%02x\n",
			objectType->Data1, objectType->Data2, objectType->Data3,
			objectType->Data4[0], objectType->Data4[1], objectType->Data4[2], objectType->Data4[3],
			objectType->Data4[4], objectType->Data4[5], objectType->Data4[6], objectType->Data4[7]);
	}
}

// Function to display ACE information
void DisplayAceInformation(PACL pSACL, BOOL isSingleCheck, BOOL verbose) {
	if (isSingleCheck) {
		if (pSACL == NULL || pSACL->AceCount == 0) {  // Check if the SACL is empty
			wprintf(L"No SACL or empty SACL.\n");
			return;
		}
	}

	for (DWORD i = 0; i < pSACL->AceCount; i++) {
		LPVOID pAce;
		if (GetAce(pSACL, i, &pAce)) {
			ACE_HEADER* aceHeader = (ACE_HEADER*)pAce;  // Get the ACE header
			PSID pSid = NULL;
			// Skip inherited ACEs unless verbose flag is set
			if ((aceHeader->AceFlags & INHERITED_ACE) && !verbose) {
				continue;
			}
			// Check auditing conditions: success, failure, or both
			BOOL auditsOnSuccess = aceHeader->AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG;
			BOOL auditsOnFailure = aceHeader->AceFlags & FAILED_ACCESS_ACE_FLAG;
			// Skip ACEs that don't audit on success or failure unless verbose flag is set
			if (!auditsOnSuccess && !auditsOnFailure && !verbose) {
				continue;
			}
			wprintf(L"SACL Entry %d Auditing on: ", i + 1);
			if (auditsOnSuccess && auditsOnFailure) {
				wprintf(L"Success and Failure\n");
			}
			else if (auditsOnSuccess) {
				wprintf(L"Success\n");
			}
			else if (auditsOnFailure) {
				wprintf(L"Failure\n");
			}
			else {
				wprintf(L"None (not auditing on success or failure)\n");
			}

			// Check for inherited ACE
			if (aceHeader->AceFlags & INHERITED_ACE) {
				wprintf(L"  Inherited ACE\n");

				// Display inheritance properties if applicable
				if (aceHeader->AceFlags & OBJECT_INHERIT_ACE) {
					if (verbose) {
						wprintf(L"    Inheritance: Applies to child objects\n");
					}
				}
				if (aceHeader->AceFlags & CONTAINER_INHERIT_ACE) {
					if (verbose) {
						wprintf(L"    Inheritance: Applies to child containers\n");
					}
				}
				if (aceHeader->AceFlags & NO_PROPAGATE_INHERIT_ACE) {
					if (verbose) {
						wprintf(L"    Inheritance: Does not propagate to further child objects\n");
					}
				}
				if (aceHeader->AceFlags & INHERIT_ONLY_ACE) {
					if (verbose) {
						wprintf(L"    Inheritance: ACE is inherited only, does not apply to current object\n");
					}
				}
			}
			else {
				wprintf(L"  Direct ACE (not inherited)\n");
			}

			// Check for SYSTEM_AUDIT_ACE_TYPE for general auditing permissions
			if (aceHeader->AceType == SYSTEM_AUDIT_ACE_TYPE) {
				SYSTEM_AUDIT_ACE* pAuditAce = (SYSTEM_AUDIT_ACE*)pAce;
				PSID pSid = &pAuditAce->SidStart;

				if (pSid) {
					if (verbose) wprintf(L"SACL Entry %d: Attempting SID resolution.\n", i + 1);
					VerifySidStructure(pSid, verbose);  // Check SID structure
					ResolveSidWithFallback(pSid);
				}
				else {
					wprintf(L"SACL Entry %d: SID not found or invalid.\n", i + 1);
				}

				// List all possible rights
				if (pAuditAce->Mask & DELETE)						wprintf(L"  Auditing: Delete\n");
				if (pAuditAce->Mask & READ_CONTROL)					wprintf(L"  Auditing: Read Control\n");
				if (pAuditAce->Mask & WRITE_DAC)					wprintf(L"  Auditing: Write DAC\n");
				if (pAuditAce->Mask & WRITE_OWNER)					wprintf(L"  Auditing: Write Owner\n");
				if (pAuditAce->Mask & SYNCHRONIZE)					wprintf(L"  Auditing: Synchronize\n");

				// Standard rights
				if (pAuditAce->Mask & STANDARD_RIGHTS_READ)			wprintf(L"  Auditing: Standard Rights Read\n");
				if (pAuditAce->Mask & STANDARD_RIGHTS_WRITE)		wprintf(L"  Auditing: Standard Rights Write\n");
				if (pAuditAce->Mask & STANDARD_RIGHTS_EXECUTE)		wprintf(L"  Auditing: Standard Rights Execute\n");
				if (pAuditAce->Mask & STANDARD_RIGHTS_REQUIRED)		wprintf(L"  Auditing: Standard Rights Required\n");
				if (pAuditAce->Mask & STANDARD_RIGHTS_ALL)			wprintf(L"  Auditing: Standard Rights All\n");

				// Generic rights
				if (pAuditAce->Mask & GENERIC_READ) 				wprintf(L"  Auditing: Generic Read\n");
				if (pAuditAce->Mask & GENERIC_WRITE)				wprintf(L"  Auditing: Generic Write\n");
				if (pAuditAce->Mask & GENERIC_EXECUTE)			 	wprintf(L"  Auditing: Generic Execute\n");
				if (pAuditAce->Mask & GENERIC_ALL) 					wprintf(L"  Auditing: Generic All\n");

				// File and directory specific rights
				if (pAuditAce->Mask & FILE_READ_DATA)				wprintf(L"  Auditing: Read Data / List Directory\n");
				if (pAuditAce->Mask & FILE_WRITE_DATA) 				wprintf(L"  Auditing: Write Data / Add File\n");
				if (pAuditAce->Mask & FILE_APPEND_DATA)				wprintf(L"  Auditing: Append Data / Add Subdirectory\n");
				if (pAuditAce->Mask & FILE_READ_EA)					wprintf(L"  Auditing: Read Extended Attributes\n");
				if (pAuditAce->Mask & FILE_WRITE_EA)				wprintf(L"  Auditing: Write Extended Attributes\n");
				if (pAuditAce->Mask & FILE_EXECUTE)					wprintf(L"  Auditing: Execute / Traverse\n");
				if (pAuditAce->Mask & FILE_DELETE_CHILD)			wprintf(L"  Auditing: Delete Child\n");
				if (pAuditAce->Mask & FILE_READ_ATTRIBUTES) 		wprintf(L"  Auditing: Read Attributes\n");
				if (pAuditAce->Mask & FILE_WRITE_ATTRIBUTES)		wprintf(L"  Auditing: Write Attributes\n");

				// Active Directory-specific rights
				if (pAuditAce->Mask & ADS_RIGHT_DS_CREATE_CHILD) 	wprintf(L"  Auditing: Create Child\n");
				if (pAuditAce->Mask & ADS_RIGHT_DS_DELETE_CHILD)	wprintf(L"  Auditing: Delete Child\n");
				if (pAuditAce->Mask & ADS_RIGHT_ACTRL_DS_LIST)		wprintf(L"  Auditing: List Contents\n");
				if (pAuditAce->Mask & ADS_RIGHT_DS_SELF)			wprintf(L"  Auditing: Self\n");
				if (pAuditAce->Mask & ADS_RIGHT_DS_READ_PROP)		wprintf(L"  Auditing: Read Property\n");
				if (pAuditAce->Mask & ADS_RIGHT_DS_WRITE_PROP)		wprintf(L"  Auditing: Write Property\n");
				if (pAuditAce->Mask & ADS_RIGHT_DS_DELETE_TREE) 	wprintf(L"  Auditing: Delete Tree\n");
				if (pAuditAce->Mask & ADS_RIGHT_DS_LIST_OBJECT) 	wprintf(L"  Auditing: List Object\n");
				if (pAuditAce->Mask & ADS_RIGHT_DS_CONTROL_ACCESS)	wprintf(L"  Auditing: Control Access\n");

			}
			// Check for GUID-based SYSTEM_AUDIT_OBJECT_ACE_TYPE for attribute-specific rights

			else if (aceHeader->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
				SYSTEM_AUDIT_OBJECT_ACE* pAuditObjectAce = (SYSTEM_AUDIT_OBJECT_ACE*)pAce;
				// Determine SidStart dynamically based on Flags
				PSID pSid = CalculateSidStart(pAuditObjectAce);

				if (pSid) {
					if (verbose) wprintf(L"SACL Entry %d: Attempting SID resolution.\n", i + 1);
					VerifySidStructure(pSid, verbose);  // Check SID structure
					ResolveSidWithFallback(pSid);
				}
				else {
					wprintf(L"SACL Entry %d: SID not found or invalid.\n", i + 1);
				}

				// Debug output to display the ACE and GUID type
				wprintf(L"Processing SYSTEM_AUDIT_OBJECT_ACE_TYPE ACE.\n");

				if (!IsEqualGUID(&pAuditObjectAce->ObjectType, &GUID_NULL)) {
					ProcessGUIDFromAce(&pAuditObjectAce->ObjectType, pAuditObjectAce->Mask, verbose);
				}
				else {
					wprintf(L"  No specific ObjectType GUID (GUID_NULL).\n");
				}

				// Display any standard rights within object-specific ACEs for completeness
				if (pAuditObjectAce->Mask & GENERIC_READ) {
					wprintf(L"  Auditing: Generic Read\n");
				}
				if (pAuditObjectAce->Mask & GENERIC_WRITE) {
					wprintf(L"  Auditing: Generic Write\n");
				}
			}


			else {
				wprintf(L"SACL Entry %d: Not an audit ACE.\n", i + 1);
			}
		}
		else {
			wprintf(L"Failed to retrieve ACE %d.\n", i + 1);
		}
	}
}

// Check SACL for a file or directory
void CheckSACLForFile(LPCWSTR path, BOOL isSingleCheck, BOOL verbose) {
	PSECURITY_DESCRIPTOR pSD = NULL;
	BOOL bSaclPresent = FALSE;
	BOOL bSaclDefaulted = FALSE;
	PACL pSACL = NULL;
	DWORD dwResult;

	// Get the SACL for the file or directory
	dwResult = GetNamedSecurityInfo(path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSACL, &pSD);

	if (dwResult == ERROR_SUCCESS) {  // Check if the SACL was retrieved successfully
		if (GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted) && bSaclPresent) {  // Check if the SACL is present
			if (pSACL->AceCount != 0) {  // Check if the SACL is empty
				wprintf(L"SACL found on file/directory: %s\n", path);
			}
			DisplayAceInformation(pSACL, isSingleCheck, verbose);  // Display the ACE information
		}
		else {
			if (isSingleCheck) {
				wprintf(L"No SACL or empty SACL on file/directory: %s\n", path);
			}
		}
		LocalFree(pSD);
	}
	else {
		if (isSingleCheck) {
			wprintf(L"Failed to retrieve SACL for file/directory: %s, Error: %lu\n", path, dwResult);
		}
	}
}

// Check SACL for a registry key
BOOL CheckSACLForRegistryKey(HKEY hKey, LPCWSTR subKey, BOOL isSingleCheck, BOOL verbose) {
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dwSDSize = 0;
	DWORD dwResult;
	BOOL bSaclPresent = FALSE;
	BOOL bSaclDefaulted = FALSE;
	PACL pSACL = NULL;

	// First call to RegGetKeySecurity to get the size needed for the security descriptor
	dwResult = RegGetKeySecurity(hKey, SACL_SECURITY_INFORMATION, NULL, &dwSDSize);

	if (dwResult == ERROR_INSUFFICIENT_BUFFER) {
		// Allocate the necessary buffer size
		pSD = (PSECURITY_DESCRIPTOR)malloc(dwSDSize);
		if (pSD == NULL) {
			if (isSingleCheck) {
				wprintf(L"Failed to allocate memory for security descriptor.\n");
			}
			return TRUE;  // Return TRUE to continue recursion, as we couldnt retrieve the SACL
		}

		// Second call to RegGetKeySecurity with the allocated buffer
		dwResult = RegGetKeySecurity(hKey, SACL_SECURITY_INFORMATION, pSD, &dwSDSize);
	}

	if (dwResult == ERROR_SUCCESS) {
		// Now we can retrieve the SACL from the security descriptor
		if (GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted) && bSaclPresent && pSACL != NULL) {
			if (pSACL->AceCount > 0) {
				wprintf(L"SACL found on registry key: %s\n", subKey);

				if (isSingleCheck) {
					DisplayAceInformation(pSACL, isSingleCheck, verbose);
				}

				// Check each ACE in the SACL for auditing triggers
				for (DWORD i = 0; i < pSACL->AceCount; i++) {
					LPVOID pAce;
					if (GetAce(pSACL, i, &pAce)) {
						ACE_HEADER* aceHeader = (ACE_HEADER*)pAce;

						if (aceHeader->AceType == SYSTEM_AUDIT_ACE_TYPE) {
							SYSTEM_AUDIT_ACE* pAuditAce = (SYSTEM_AUDIT_ACE*)pAce;

							// Check if this ACE would trigger auditing on access
							if (pAuditAce->Mask & (KEY_READ | KEY_ENUMERATE_SUB_KEYS)) {
								wprintf(L"Sensitive SACL detected on key: %s. Stopping recursion.\n", subKey);
								free(pSD);
								return FALSE;  // Sensitive SACL detected; stop recursion
							}
						}
					}
				}
			}
			else if (isSingleCheck) {
				wprintf(L"No SACL or empty SACL on registry key: %s\n", subKey);
			}
		}
	}
	else {
		if (isSingleCheck) {
			wprintf(L"Failed to retrieve SACL for registry key: %s, Error: %lu\n", subKey, dwResult);
		}
	}

	if (pSD != NULL) {
		free(pSD);
	}

	return TRUE;  // Safe to continue
}

// Check SACL for a service
void CheckSACLForService(LPCWSTR serviceName, BOOL isSingleCheck, BOOL verbose) {
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);  // Open the Service Control Manager
	if (hSCManager == NULL) {  // Check if the Service Control Manager was opened successfully
		if (isSingleCheck) {
			wprintf(L"Failed to open Service Control Manager. Error: %lu\n", GetLastError());
		}
		return;
	}

	SC_HANDLE hService = OpenService(hSCManager, serviceName, READ_CONTROL | ACCESS_SYSTEM_SECURITY);  // Open the service
	if (hService == NULL) {  // Check if the service was opened successfully
		if (isSingleCheck) {
			wprintf(L"Failed to open service: %s, Error: %lu\n", serviceName, GetLastError());
		}
		CloseServiceHandle(hSCManager);
		return;
	}

	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dwBytesNeeded = 0;
	if (!QueryServiceObjectSecurity(hService, SACL_SECURITY_INFORMATION, pSD, 0, &dwBytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {  // Query the SACL size
		pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwBytesNeeded);  // Allocate memory for the security descriptor
		if (QueryServiceObjectSecurity(hService, SACL_SECURITY_INFORMATION, pSD, dwBytesNeeded, &dwBytesNeeded)) {  // Query the SACL
			BOOL bSaclPresent = FALSE;
			BOOL bSaclDefaulted = FALSE;
			PACL pSACL = NULL;

			if (GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted) && bSaclPresent) {  // Check if the SACL is present
				wprintf(L"SACL found on service: %s\n", serviceName);
				DisplayAceInformation(pSACL, isSingleCheck, verbose);  // Display the ACE information
			}
			else if (isSingleCheck) {
				wprintf(L"No SACL or empty SACL on service: %s\n", serviceName);
			}
		}
		LocalFree(pSD);
	}
	else {
		if (isSingleCheck) {
			wprintf(L"Failed to retrieve SACL for service: %s, Error: %lu\n", serviceName, GetLastError());
		}
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}

// Function to check if any SID in the current user's token matches the SIDs in the SACL
BOOL CheckDirectorySACL(LPCWSTR directory, BOOL verbose) {
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pSACL = NULL;
	BOOL saclPresent = FALSE;
	BOOL saclDefaulted = FALSE;

	// Get the SACL of the directory
	DWORD result = GetNamedSecurityInfoW(directory, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSACL, &pSD);

	if (result != ERROR_SUCCESS) {
		if (verbose) {
			wprintf(L"Failed to retrieve SACL for directory: %s (Error: %lu)\n", directory, result);
		}
		return FALSE; // Assume no SACL triggers
	}

	if (GetSecurityDescriptorSacl(pSD, &saclPresent, &pSACL, &saclDefaulted) && saclPresent) {  // Check if the SACL is present
		wprintf(L"SACL found on directory: %s\n", directory);
	}

	// Check if SACL is present
	if (!saclPresent || !pSACL) {
		if (verbose) {
			wprintf(L"No SACL present for directory: %s\n", directory);
		}
		LocalFree(pSD);
		return FALSE; // No SACL means no triggers
	}

	// Open the current process token
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		if (verbose) {
			wprintf(L"Failed to open process token. Error: %lu\n", GetLastError());
		}
		LocalFree(pSD);
		return FALSE; // Assume safe if we can't retrieve the token
	}

	// Retrieve the token groups (SIDs) from the token
	DWORD tokenInfoLength = 0;
	GetTokenInformation(hToken, TokenGroups, NULL, 0, &tokenInfoLength);
	PTOKEN_GROUPS pTokenGroups = (PTOKEN_GROUPS)malloc(tokenInfoLength);

	if (pTokenGroups == NULL ||
		!GetTokenInformation(hToken, TokenGroups, pTokenGroups, tokenInfoLength, &tokenInfoLength)) {
		if (verbose) {
			wprintf(L"Failed to retrieve token groups. Error: %lu\n", GetLastError());
		}
		CloseHandle(hToken);
		LocalFree(pSD);
		if (pTokenGroups) free(pTokenGroups);
		return FALSE; // Assume safe if we can't retrieve token groups
	}

	// Iterate over the ACEs in the SACL
	for (DWORD i = 0; i < pSACL->AceCount; i++) {
		LPVOID pAce = NULL;
		if (GetAce(pSACL, i, &pAce)) {
			PACE_HEADER pAceHeader = (PACE_HEADER)pAce;

			// Check if it's a SYSTEM_AUDIT_ACE
			if (pAceHeader->AceType == SYSTEM_AUDIT_ACE_TYPE) {
				PSYSTEM_AUDIT_ACE pAuditAce = (PSYSTEM_AUDIT_ACE)pAce;

				// Extract the SID from the ACE
				PSID pAceSID = (PSID)&pAuditAce->SidStart;

				// Compare the ACE SID with each SID in the token
				for (DWORD j = 0; j < pTokenGroups->GroupCount; j++) {
					PSID pTokenSID = pTokenGroups->Groups[j].Sid;

					// Check if the SIDs match
					if (EqualSid(pAceSID, pTokenSID)) {
						wprintf(L"Detected matching SID in SACL for directory: %s\n", directory);
						DisplayAceInformation(pSACL, TRUE, verbose);  // Display the ACE information

						// Free resources and return TRUE to indicate a potential SACL trigger
						free(pTokenGroups);
						CloseHandle(hToken);
						LocalFree(pSD);
						return TRUE; // Trigger detected
					}
				}
			}
		}
	}

	// Free resources and return FALSE (no trigger detected)
	free(pTokenGroups);
	CloseHandle(hToken);
	LocalFree(pSD);
	return FALSE;
}

// Function to check the SACL for a specific Active Directory object
HKEY GetRegistryHive(LPCWSTR path, LPCWSTR* subKey) {
	if ((_wcsnicmp(path, L"HKEY_LOCAL_MACHINE\\", 18) == 0)) {
		*subKey = path + 18;
		return HKEY_LOCAL_MACHINE;
	}
	else if (_wcsnicmp(path, L"HKEY_CURRENT_USER\\", 17) == 0) {
		*subKey = path + 17;
		return HKEY_CURRENT_USER;
	}
	else if (_wcsnicmp(path, L"HKEY_CLASSES_ROOT\\", 18) == 0) {
		*subKey = path + 18;
		return HKEY_CLASSES_ROOT;
	}
	else if (_wcsnicmp(path, L"HKEY_USERS\\", 11) == 0) {
		*subKey = path + 11;
		return HKEY_USERS;
	}
	else if (_wcsnicmp(path, L"HKEY_CURRENT_CONFIG\\", 20) == 0) {
		*subKey = path + 20;
		return HKEY_CURRENT_CONFIG;
	}
	else {
		return NULL;
	}
}

// Enumerate registry keys
void EnumerateRegistryKeys(HKEY hKey, LPCWSTR displayPath, LPCWSTR subKey, BOOL opsec, BOOL verbose) {
	HKEY hSubKey;
	DWORD dwIndex = 0;
	WCHAR subKeyName[MAX_PATH];
	DWORD subKeyNameSize;

	// Open the subKey (if provided) without ACCESS_SYSTEM_SECURITY for enumeration
	if (subKey == NULL || *subKey == L'\0') {
		hSubKey = hKey;  // Root hive handle directly
	}
	else {
		// Open subkeys normally without prefixing with the hive name
		LONG lResult = RegOpenKeyEx(hKey, subKey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hSubKey);
		if (lResult != ERROR_SUCCESS) {
			if (verbose) {
				wprintf(L"Failed to open registry key: %s\\%s. Error: %lu\n", displayPath, subKey, lResult);
			}
			return;
		}
	}
	// Check SACL for the current key
	HKEY hSaclKey;
	if (RegOpenKeyEx(hSubKey, NULL, 0, READ_CONTROL | ACCESS_SYSTEM_SECURITY, &hSaclKey) == ERROR_SUCCESS) {
		CheckSACLForRegistryKey(hSaclKey, displayPath, 1, verbose);
		if (!CheckSACLForRegistryKey(hSubKey, displayPath, 0, verbose) && opsec) {
			wprintf(L"Skipping subkeys under: %s due to sensitive SACL.\n", displayPath);
			if (subKey && *subKey) RegCloseKey(hSubKey);
			return;  // Stop recursion
		}
		RegCloseKey(hSaclKey);
	}
	else {
		if (verbose) {
			wprintf(L"Unable to check SACL for key: %s\n", displayPath);
		}
	}

	// Enumerate subkeys
	while (TRUE) {
		subKeyNameSize = MAX_PATH;
		LONG lResult = RegEnumKeyEx(hSubKey, dwIndex, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL);

		if (lResult == ERROR_NO_MORE_ITEMS) break;
		if ((lResult != ERROR_SUCCESS) && verbose) {
			wprintf(L"Failed to enumerate subkey at index %d. Error: %lu\n", dwIndex, lResult);
			break;
		}

		// Construct the display path for user output
		WCHAR newDisplayPath[MAX_PATH];
		swprintf(newDisplayPath, MAX_PATH, L"%s\\%s", displayPath, subKeyName);

		// Recursively enumerate subkeys, using `subKeyName` as the next `subKey` for RegOpenKeyEx
		EnumerateRegistryKeys(hSubKey, newDisplayPath, subKeyName, opsec, verbose);
		dwIndex++;
	}

	// Close `hSubKey` if it was opened in this function (i.e., not a root hive)
	if (subKey && *subKey) {
		RegCloseKey(hSubKey);
	}
}


void EnumerateServices(BOOL verbose) {
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if ((hSCManager == NULL) && verbose) {
		wprintf(L"Failed to open Service Control Manager. Error: %lu\n", GetLastError());
		return;
	}

	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;

	EnumServicesStatus(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle);  // Get the required buffer size

	if (GetLastError() == ERROR_MORE_DATA) {  // Check if the buffer size is too small
		LPENUM_SERVICE_STATUS pServiceStatus = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, dwBytesNeeded);  // Allocate memory for the service status

		if (EnumServicesStatus(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, pServiceStatus, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle)) {  // Enumerate the services
			for (DWORD i = 0; i < dwServicesReturned; i++) {  // Loop through each service
				CheckSACLForService(pServiceStatus[i].lpServiceName, FALSE, verbose);  // Check the SACL for the service
			}
		}

		LocalFree(pServiceStatus);
	}

	CloseServiceHandle(hSCManager);
}

void EnumerateFiles(LPCWSTR directory, BOOL opsec, BOOL verbose) {
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	WCHAR directoryPath[MAX_PATH];
	swprintf(directoryPath, MAX_PATH, L"%s\\*", directory);

	// Check the directory SACL if the opsec flag is enabled
	if (opsec) {
		if (CheckDirectorySACL(directory, verbose)) {
			if (verbose) {
				wprintf(L"Skipping directory due to SACL auditing: %s\n", directory);
			}
			return;
		}
	}

	hFind = FindFirstFile(directoryPath, &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		wprintf(L"Failed to open directory: %s\n", directory);
		return;
	}

	do {
		// Skip "." and ".." directories to avoid self-referencing
		if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0) {
			WCHAR fullPath[MAX_PATH];
			swprintf(fullPath, MAX_PATH, L"%s\\%s", directory, findFileData.cFileName);

			// Check if it's a reparse point (e.g., symbolic link or junction) to avoid recursive loops
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				if (verbose) {
					wprintf(L"Skipping symbolic link or junction: %s\n", fullPath);
				}
				continue;  // Skip this entry
			}

			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				// Recurse into subdirectories
				EnumerateFiles(fullPath, opsec, verbose);
			}
			else {
				// Check file SACL if it's a regular file
				CheckSACLForFile(fullPath, FALSE, verbose);
			}
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	FindClose(hFind);
}

void EnumerateFilesInDirectory(LPCWSTR directory, BOOL opsec, BOOL verbose) {
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	WCHAR directoryPath[MAX_PATH];
	swprintf(directoryPath, MAX_PATH, L"%s\\*", directory);

	// Check the directory SACL if the opsec flag is enabled
	if (opsec) {
		if (CheckDirectorySACL(directory, verbose)) {
			wprintf(L"Skipping directory due to SACL auditing: %s\n", directory);
			return;
		}
	}

	hFind = FindFirstFile(directoryPath, &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		wprintf(L"Failed to open directory: %s\n", directory);
		return;
	}

	do {
		if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			WCHAR fullPath[MAX_PATH];
			swprintf(fullPath, MAX_PATH, L"%s\\%s", directory, findFileData.cFileName);
			CheckSACLForFile(fullPath, TRUE, verbose);
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	FindClose(hFind);
}

// Modified GetSACLFromADObject function to retrieve and display the SACL
BOOL GetSACLFromADObject(LPCWSTR objectName, BOOL verbose) {
	HRESULT hr;
	IDirectoryObject* pDirObject = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pSACL = NULL;
	BOOL saclPresent = FALSE, saclDefaulted = FALSE;
	BOOL hasEffectiveACE = FALSE;

	// Bind to the specific AD object as an IDirectoryObject
	hr = ADsOpenObject(objectName, NULL, NULL, ADS_SECURE_AUTHENTICATION, &IID_IDirectoryObject, (void**)&pDirObject);
	if (FAILED(hr)) {
		if (verbose) {
			wprintf(L"Failed to bind to object %ls. HRESULT: 0x%x\n", objectName, hr);
		}
		return FALSE;
	}
	else {
		if (verbose) {
			wprintf(L"Successfully bound to object: %ls\n", objectName);
		}
	}

	// Retrieve the security descriptor using GetNamedSecurityInfo
	DWORD result = GetNamedSecurityInfoW(objectName, SE_DS_OBJECT_ALL, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSACL, &pSD);

	if (result != ERROR_SUCCESS) {
		if (verbose) {
			wprintf(L"GetNamedSecurityInfo failed for %ls. Error: %lu\n", objectName, result);
		}
		pDirObject->lpVtbl->Release(pDirObject);
		return FALSE;
	}
	else {
		if (verbose) {
			wprintf(L"GetNamedSecurityInfo succeeded for %ls.\n", objectName);
		}
	}

	// Check if SACL is present and contains effective ACEs
	if (pSACL && pSACL->AceCount > 0) {
		// Loop through each ACE in the SACL to check for effective entries
		for (DWORD i = 0; i < pSACL->AceCount; i++) {
			LPVOID pAce;
			if (GetAce(pSACL, i, &pAce)) {
				ACE_HEADER* aceHeader = (ACE_HEADER*)pAce;

				// Effective ACE conditions:
				// 1. Non-inherited ACEs are effective.
				// 2. Inherited ACEs are effective only if they have success/failure flags and are not "inherit-only".
				if (!(aceHeader->AceFlags & INHERITED_ACE) ||  // Non-inherited ACE
					((aceHeader->AceFlags & (SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG)) &&  // Has audit flags
						!(aceHeader->AceFlags & INHERIT_ONLY_ACE))) {  // Applies to this object, not just children
					hasEffectiveACE = TRUE;
					break;
				}
			}
		}
	}

	// Display the SACL if it has effective entries
	if (hasEffectiveACE) {
		wprintf(L"\nSACL for object %ls:\n", objectName);
		DisplayAceInformation(pSACL, TRUE, verbose);
	}
	else if (verbose) {
		wprintf(L"No effective SACL found for object %ls.\n", objectName);
	}

	// Clean up
	if (pSD) LocalFree(pSD);
	pDirObject->lpVtbl->Release(pDirObject);

	return TRUE;
}

// Main AD enumeration function
BOOL EnumerateAndRetrieveSACLs(LPCWSTR ldapPath, BOOL recurse, BOOL verbose) {
	IDispatch* pDisp = NULL;
	IADsContainer* pContainer = NULL;
	IEnumVARIANT* pEnum = NULL;
	HRESULT hr;
	VARIANT var;
	ULONG lFetch;

	// Initialize COM
	CoInitialize(NULL);

	// Bind to the provided LDAP path
	hr = ADsOpenObject(ldapPath, NULL, NULL, ADS_SECURE_AUTHENTICATION, &IID_IDispatch, (void**)&pDisp);
	if (FAILED(hr)) {
		wprintf(L"Failed to bind to LDAP path %ls. Error: 0x%x\n", ldapPath, hr);
		wprintf(L"        Expected Format: \"LDAP://CN=username,CN=Users,DC=contoso,DC=local\"\n");
		CoUninitialize();
		return FALSE;
	}

	// Try to query the IADsContainer interface to see if it's a container
	hr = pDisp->lpVtbl->QueryInterface(pDisp, &IID_IADsContainer, (void**)&pContainer);
	if (SUCCEEDED(hr)) {
		// Try enumerating to see if there are any child objects
		hr = ADsBuildEnumerator(pContainer, &pEnum);
		if (FAILED(hr) || ADsEnumerateNext(pEnum, 1, &var, &lFetch) != S_OK) {
			if (verbose) {
				wprintf(L"Failed to enumerate child objects for container: %ls\n", ldapPath);
			}
			// If enumeration fails or finds no children, treat as single object
			GetSACLFromADObject(ldapPath, verbose);

			// Clean up and release resources
			if (pEnum) pEnum->lpVtbl->Release(pEnum);
			pContainer->lpVtbl->Release(pContainer);
			pDisp->lpVtbl->Release(pDisp);
			CoUninitialize();
			return TRUE;
		}

		// If child objects are found, enumerate the container
		wprintf(L"Enumerating container: %ls\n", ldapPath);

		do {
			if (V_VT(&var) == VT_DISPATCH) {
				IADs* pObject = NULL;

				// Query IADs interface from the VARIANT
				hr = V_DISPATCH(&var)->lpVtbl->QueryInterface(V_DISPATCH(&var), &IID_IADs, (void**)&pObject);
				if (SUCCEEDED(hr)) {
					BSTR bstrName;
					pObject->lpVtbl->get_ADsPath(pObject, &bstrName);

					if (verbose) {
						wprintf(L"\nRetrieving SACL for: %ls\n", bstrName);
					}
					GetSACLFromADObject(bstrName, verbose);

					// If recurse is enabled, check if the object is a container and call recursively
					if (recurse) {
						IADsContainer* pChildContainer = NULL;
						hr = pObject->lpVtbl->QueryInterface(pObject, &IID_IADsContainer, (void**)&pChildContainer);
						if (SUCCEEDED(hr)) {
							if (verbose) {
								wprintf(L"Recursively enumerating container: %ls\n", bstrName);
							}
							EnumerateAndRetrieveSACLs(bstrName, recurse, verbose);  // Recursive call
							pChildContainer->lpVtbl->Release(pChildContainer);
						}
					}

					SysFreeString(bstrName);
					pObject->lpVtbl->Release(pObject);
				}
			}
			VariantClear(&var);
		} while (ADsEnumerateNext(pEnum, 1, &var, &lFetch) == S_OK);

		pEnum->lpVtbl->Release(pEnum);
		pContainer->lpVtbl->Release(pContainer);
	}
	else {
		// If the object is not a container, treat it as a single object
		if (verbose) {
			wprintf(L"\nRetrieving SACL for single object: %ls\n", ldapPath);
		}
		GetSACLFromADObject(ldapPath, verbose);
	}

	pDisp->lpVtbl->Release(pDisp);
	CoUninitialize();

	return TRUE;
}

void HelpMenu() {
	wprintf(L"Usage: SACL_Scanner.exe [option] [target]\n");
	wprintf(L"Options:\n");
	wprintf(L"  -r  : Check all registry keys in a hive or a specific registry key\n");
	wprintf(L"        Expected Hive Format: HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG\n");
	wprintf(L"  -s  : Check all services or a specific service\n");
	wprintf(L"  -f  : Check all files and directories, a specific file/directory, or only files in a specific directory (with -d)\n");
	wprintf(L"  -d  : Check all files in a specific directory\n");
	wprintf(L"  -a  : Check objects in an Active Directory path\n");
	wprintf(L"        Expected Format: \"LDAP://CN=username,CN=Users,DC=contoso,DC=local\"\n");
	wprintf(L"  -recursive : Enable recursive mode for Active Directory\n");
	wprintf(L"  -opsec : Enable OPSEC safe mode\n");
	wprintf(L"  -v  : Enable verbose mode\n");
}

int wmain(int argc, wchar_t* argv[]) {
	LPCWSTR hiveName = NULL;
	LPCWSTR directory = NULL;
	LPCWSTR service = NULL;
	LPCWSTR fileName = NULL;
	LPCWSTR ldapPath = NULL;
	BOOL opsec = FALSE;
	BOOL recurse = FALSE;
	BOOL registryMode = FALSE;
	BOOL serviceMode = FALSE;
	BOOL fileMode = FALSE;
	BOOL directoryMode = FALSE;
	BOOL activeDirectoryMode = FALSE;
	BOOL isSingleCheck = FALSE;
	BOOL verboseMode = FALSE;

	if (argc < 2 || argc > 5) {
		HelpMenu();
		return 1;
	}
	// Loop through arguments to identify flags and parameters
	for (int i = 1; i < argc; i++) {
		if (_wcsicmp(argv[i], L"-r") == 0) {
			registryMode = TRUE;  // Set mode to registry
			if (i + 1 < argc) {  // Ensure there's another argument after "-r"
				hiveName = argv[++i];  // Get the hive name immediately following "-r"
			}
			else {
				wprintf(L"Error: Hive or key name required after -r\n");
				return 1;
			}
		}
		else if (_wcsicmp(argv[i], L"-s") == 0) {
			serviceMode = TRUE;  // Set mode to service
			if (i + 1 < argc) {  // Check for an argument after "-s"
				isSingleCheck = TRUE;
				service = argv[++i];  // Get the service name immediately following "-s"
			}
		}
		else if (_wcsicmp(argv[i], L"-f") == 0) {
			fileMode = TRUE;  // Set mode to file
			if (i + 1 < argc) {  // Check for an argument after "-f"
				fileName = argv[++i];  // Get the file name immediately following "-f"
			}
		}
		else if (_wcsicmp(argv[i], L"-d") == 0) {
			directoryMode = TRUE;
			if (i + 1 < argc) {  // Check for an argument after "-d"
				isSingleCheck = TRUE;
				directory = argv[++i];  // Get the directory name immediately following "-d"
			}
		}
		else if (_wcsicmp(argv[i], L"-a") == 0) {
			activeDirectoryMode = TRUE;
			if (i + 1 < argc) {  // Check for an argument after "-a"
				ldapPath = argv[++i];  // Get the LDAP path immediately following "-a"
			}
		}
		else if (_wcsicmp(argv[i], L"-recursive") == 0) {
			recurse = TRUE;  // Enable AD recursive  mode
		}
		else if (_wcsicmp(argv[i], L"-opsec") == 0) {
			opsec = TRUE;  // Enable opsec safe mode
		}
		else if (_wcsicmp(argv[i], L"-v") == 0) {
			verboseMode = TRUE;  // Enable verbose mode
		}
		else if (_wcsicmp(argv[i], L"-h") == 0) {
			HelpMenu();
			return 1;
		}
		else {
			wprintf(L"Unknown argument: %s\n", argv[i]);
			HelpMenu();
			return 1;
		}
	}

	if (registryMode) {
		if (!EnablePrivilege(SE_SECURITY_NAME)) {
			wprintf(L"Failed to enable the SE_SECURITY_NAME privilege.\n");
			return 1;
		}
		LPCWSTR subKey = NULL;
		HKEY hKey = GetRegistryHive(hiveName, &subKey);

		if (hKey == NULL) {
			wprintf(L"Invalid registry hive specified in path: %s\n", hiveName);
			return 1;
		}
		if (subKey == NULL || *subKey == L'\0') {
			// Scan the entire registry hive
			wprintf(L"Scanning entire registry hive: %s\n", hiveName);
			EnumerateRegistryKeys(hKey, hiveName, NULL, opsec, verboseMode);  // Start with an empty subKey for the root
		}
		else {
			// Strip leading backslash if present
			if (*subKey == L'\\') {
				subKey++;
			}

			wprintf(L"Registry Hive: %p, SubKey: %s\n", hKey, subKey);

			HKEY hOpenedKey;
			if (RegOpenKeyEx(hKey, subKey, 0, KEY_READ | READ_CONTROL | ACCESS_SYSTEM_SECURITY | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hOpenedKey) == ERROR_SUCCESS) {
				CheckSACLForRegistryKey(hOpenedKey, subKey, TRUE, verboseMode);
				RegCloseKey(hOpenedKey);
			}
			else {
				wprintf(L"Failed to open registry key: %s\n", hiveName);
			}
		}
	}
	else if (serviceMode) {
		if (!EnablePrivilege(SE_SECURITY_NAME)) {
			wprintf(L"Failed to enable the SE_SECURITY_NAME privilege.\n");
			return 1;
		}
		if (isSingleCheck) {
			// Check specific service
			CheckSACLForService(service, TRUE, verboseMode);
		}
		else {
			// Check all services
			wprintf(L"Checking all services...\n");
			EnumerateServices(verboseMode);
		}
	}
	else if (fileMode) {
		if (!EnablePrivilege(SE_SECURITY_NAME)) {
			wprintf(L"Failed to enable the SE_SECURITY_NAME privilege.\n");
			return 1;
		}
		// Check specific file or directory
		CheckSACLForFile(fileName, TRUE, verboseMode);

	}
	else if (directoryMode) {
		if (!EnablePrivilege(SE_SECURITY_NAME)) {
			wprintf(L"Failed to enable the SE_SECURITY_NAME privilege.\n");
			return 1;
		}
		if (isSingleCheck) {
			// Check only files in a specific directory
			EnumerateFilesInDirectory(directory, opsec, verboseMode);
		}
		else {
			// Check all files and directories
			wprintf(L"Checking all files and directories...\n");
			EnumerateFiles(L"C:\\", opsec, verboseMode);
		}
	}
	else if (activeDirectoryMode) {
		EnumerateAndRetrieveSACLs(ldapPath, recurse, verboseMode);
	}
	else {
		wprintf(L"Invalid option.\n");
	}

	return 0;
}
