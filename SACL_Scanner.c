#include <windows.h>
#include <stdio.h>
#include <aclapi.h>
#include <tchar.h>


BOOL EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        wprintf(L"Failed to open process token. Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        wprintf(L"Failed to lookup privilege value. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        wprintf(L"Failed to adjust token privileges. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        wprintf(L"The token does not have the specified privilege. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

void DisplayAceInformation(PACL pSACL, BOOL isSingleCheck) {
    if (isSingleCheck) {
        if (pSACL == NULL || pSACL->AceCount == 0) {
            wprintf(L"No SACL or empty SACL.\n");
            return;
        }
    }

    for (DWORD i = 0; i < pSACL->AceCount; i++) {
        LPVOID pAce;
        if (GetAce(pSACL, i, &pAce)) {
            ACE_HEADER* aceHeader = (ACE_HEADER*)pAce;

            if (aceHeader->AceType == SYSTEM_AUDIT_ACE_TYPE) {
                SYSTEM_AUDIT_ACE* pAuditAce = (SYSTEM_AUDIT_ACE*)pAce;
                PSID pSid = &pAuditAce->SidStart;

                WCHAR name[256];
                WCHAR domain[256];
                DWORD nameSize = sizeof(name) / sizeof(WCHAR);
                DWORD domainSize = sizeof(domain) / sizeof(WCHAR);
                SID_NAME_USE sidType;

                if (LookupAccountSid(NULL, pSid, name, &nameSize, domain, &domainSize, &sidType)) {
                    wprintf(L"SACL Entry %d: User/Group: %s\\%s\n", i + 1, domain, name);
                }
                else {
                    wprintf(L"SACL Entry %d: Unable to lookup SID.\n", i + 1);
                }

                // Check for specific auditing permissions
                if (pAuditAce->Mask & FILE_READ_DATA) {
                    wprintf(L"  Auditing: Read Data\n");
                }
                if (pAuditAce->Mask & FILE_WRITE_DATA) {
                    wprintf(L"  Auditing: Write Data\n");
                }
                if (pAuditAce->Mask & FILE_EXECUTE) {
                    wprintf(L"  Auditing: Execute\n");
                }
                if (pAuditAce->Mask & DELETE) {
                    wprintf(L"  Auditing: Delete\n");
                }
                if (pAuditAce->Mask & WRITE_DAC) {
                    wprintf(L"  Auditing: Change Permissions\n");
                }
                if (pAuditAce->Mask & WRITE_OWNER) {
                    wprintf(L"  Auditing: Change Ownership\n");
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

void CheckSACLForFile(LPCWSTR path, BOOL isSingleCheck) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    BOOL bSaclPresent = FALSE;
    BOOL bSaclDefaulted = FALSE;
    PACL pSACL = NULL;
    DWORD dwResult;

    dwResult = GetNamedSecurityInfo(path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSACL, &pSD);

    if (dwResult == ERROR_SUCCESS) {
        if (GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted) && bSaclPresent) {
            if (pSACL->AceCount != 0) {
                wprintf(L"SACL found on file/directory: %s\n", path);
            }
            DisplayAceInformation(pSACL, isSingleCheck);
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

void CheckSACLForRegistryKey(HKEY hKey, LPCWSTR subKey, BOOL isSingleCheck) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    BOOL bSaclPresent = FALSE;
    BOOL bSaclDefaulted = FALSE;
    PACL pSACL = NULL;
    DWORD dwResult;

    dwResult = RegGetKeySecurity(hKey, SACL_SECURITY_INFORMATION, NULL, &pSD);

    if (dwResult == ERROR_SUCCESS) {
        if (GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted) && bSaclPresent && pSACL->AceCount > 0) {
            wprintf(L"SACL found on registry key: %s\n", subKey);
            DisplayAceInformation(pSACL, isSingleCheck);
        }
        else if (isSingleCheck) {
            wprintf(L"No SACL or empty SACL on registry key: %s\n", subKey);
        }
        LocalFree(pSD);
    }
    else {
        if (isSingleCheck) {
            wprintf(L"Failed to retrieve SACL for registry key: %s, Error: %lu\n", subKey, dwResult);
        }
    }
}


void CheckSACLForService(LPCWSTR serviceName, BOOL isSingleCheck) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        if (isSingleCheck) {
            wprintf(L"Failed to open Service Control Manager. Error: %lu\n", GetLastError());
        }
        return;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName, READ_CONTROL);
    if (hService == NULL) {
        if (isSingleCheck) {
            wprintf(L"Failed to open service: %s, Error: %lu\n", serviceName, GetLastError());
        }
        CloseServiceHandle(hSCManager);
        return;
    }

    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD dwBytesNeeded = 0;
    if (!QueryServiceObjectSecurity(hService, SACL_SECURITY_INFORMATION, pSD, 0, &dwBytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwBytesNeeded);
        if (QueryServiceObjectSecurity(hService, SACL_SECURITY_INFORMATION, pSD, dwBytesNeeded, &dwBytesNeeded)) {
            BOOL bSaclPresent = FALSE;
            BOOL bSaclDefaulted = FALSE;
            PACL pSACL = NULL;

            if (GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted) && bSaclPresent) {
                wprintf(L"SACL found on service: %s\n", serviceName);
                DisplayAceInformation(pSACL, isSingleCheck);
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

HKEY GetRegistryHive(LPCWSTR path, LPCWSTR* subKey) {
    if (_wcsnicmp(path, L"HKEY_LOCAL_MACHINE\\", 18) == 0) {
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

void EnumerateRegistryKeys(HKEY hKey, LPCWSTR subKey, BOOL isSingleCheck) {
    HKEY hSubKey;
    DWORD dwIndex = 0;
    WCHAR subKeyName[MAX_PATH];
    DWORD subKeyNameSize = MAX_PATH;

    if (RegOpenKeyEx(hKey, subKey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hSubKey) == ERROR_SUCCESS) {
        BOOL isSingleCheck = FALSE; // Disable extra output for mass scans
        CheckSACLForRegistryKey(hSubKey, subKey, isSingleCheck);

        while (RegEnumKeyEx(hSubKey, dwIndex, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            WCHAR fullSubKeyPath[MAX_PATH];
            swprintf(fullSubKeyPath, MAX_PATH, L"%s\\%s", subKey, subKeyName);
            EnumerateRegistryKeys(hKey, fullSubKeyPath, isSingleCheck);
            subKeyNameSize = MAX_PATH;
            dwIndex++;
        }

        RegCloseKey(hSubKey);
    }
    else {
        if (isSingleCheck) {
            wprintf(L"Failed to open registry key: %s\n", subKey);
        }
    }
}

void EnumerateServices() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        wprintf(L"Failed to open Service Control Manager. Error: %lu\n", GetLastError());
        return;
    }

    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;

    EnumServicesStatus(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle);

    if (GetLastError() == ERROR_MORE_DATA) {
        LPENUM_SERVICE_STATUS pServiceStatus = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, dwBytesNeeded);

        if (EnumServicesStatus(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, pServiceStatus, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle)) {
            for (DWORD i = 0; i < dwServicesReturned; i++) {
                CheckSACLForService(pServiceStatus[i].lpServiceName, FALSE);
            }
        }

        LocalFree(pServiceStatus);
    }

    CloseServiceHandle(hSCManager);
}

void EnumerateFiles(LPCWSTR directory) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    WCHAR directoryPath[MAX_PATH];
    swprintf(directoryPath, MAX_PATH, L"%s\\*", directory);

    hFind = FindFirstFile(directoryPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open directory: %s\n", directory);
        return;
    }

    do {
        if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0) {
            WCHAR fullPath[MAX_PATH];
            swprintf(fullPath, MAX_PATH, L"%s\\%s", directory, findFileData.cFileName);

            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                EnumerateFiles(fullPath);  // Recurse into directories
            }
            else {
                CheckSACLForFile(fullPath, FALSE);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void EnumerateFilesInDirectory(LPCWSTR directory) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    WCHAR directoryPath[MAX_PATH];
    swprintf(directoryPath, MAX_PATH, L"%s\\*", directory);

    hFind = FindFirstFile(directoryPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open directory: %s\n", directory);
        return;
    }

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            WCHAR fullPath[MAX_PATH];
            swprintf(fullPath, MAX_PATH, L"%s\\%s", directory, findFileData.cFileName);
            CheckSACLForFile(fullPath, FALSE);
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

int wmain(int argc, wchar_t* argv[]) {
    if (!EnablePrivilege(SE_SECURITY_NAME)) {
        wprintf(L"Failed to enable the SE_SECURITY_NAME privilege.\n");
        return 1;
    }

    if (argc < 2 || argc > 4) {
        wprintf(L"Usage: %s [option] [target]\n", argv[0]);
        wprintf(L"Options:\n");
        wprintf(L"  -r  : Check all registry keys or a specific registry key\n");
        wprintf(L"  -s  : Check all services or a specific service\n");
        wprintf(L"  -f  : Check all files and directories, a specific file/directory, or only files in a specific directory (with -d)\n");
        return 1;
    }

    BOOL isSingleCheck = (argc == 3);
    BOOL isDirectoryCheck = (argc == 4 && wcscmp(argv[1], L"-f") == 0 && wcscmp(argv[3], L"-d") == 0);

    if (wcscmp(argv[1], L"-r") == 0) {
        LPCWSTR subKey;
        HKEY hKey = GetRegistryHive(argv[2], &subKey);

        if (hKey == NULL) {
            wprintf(L"Invalid registry hive specified in path.\n");
            return 1;
        }

        HKEY hOpenedKey;
        if (RegOpenKeyEx(hKey, subKey, 0, KEY_READ | READ_CONTROL | ACCESS_SYSTEM_SECURITY, &hOpenedKey) == ERROR_SUCCESS) {
            CheckSACLForRegistryKey(hOpenedKey, subKey, TRUE);
            RegCloseKey(hOpenedKey);
        }
        else {
            wprintf(L"Failed to open registry key: %s\n", argv[2]);
        }
    }
    else if (wcscmp(argv[1], L"-s") == 0) {
        if (isSingleCheck) {
            // Check specific service
            CheckSACLForService(argv[2], TRUE);
        }
        else {
            // Check all services
            wprintf(L"Checking all services...\n");
            EnumerateServices();
        }
    }
    else if (wcscmp(argv[1], L"-f") == 0) {
        if (isDirectoryCheck) {
            // Check only files in a specific directory
            wprintf(L"Checking files in directory: %s\n", argv[2]);
            EnumerateFilesInDirectory(argv[2]);
        }
        else if (isSingleCheck) {
            // Check specific file or directory
            CheckSACLForFile(argv[2], TRUE);
        }
        else {
            // Check all files and directories
            wprintf(L"Checking all files and directories...\n");
            EnumerateFiles(L"C:\\");  // You can change this to any starting directory
        }
    }
    else {
        wprintf(L"Invalid option.\n");
    }

    return 0;
}
