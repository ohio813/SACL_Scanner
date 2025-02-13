# SACL Scanner

## Overview
SACL Scanner is a tool designed to scan and analyze System Access Control Lists (SACLs) across various Windows objects, such as registry keys, services, files, directories, and Active Directory paths. It provides options to perform detailed checks while maintaining operational security (OPSEC). 

**`NOTE:`** You will need the appropriate privileges to read the SACLs (i.e., SE_SECURITY_NAME for the registry/services/files/directories, AD privileges over the AD object checked)

## Usage
```bash
SACL_Scanner.exe [option] [target]
```

### Options
- **`-r`**: Check all registry keys in a hive or a specific registry key. Expected hives include `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_CLASSES_ROOT`, `HKEY_USERS`, and `HKEY_CURRENT_CONFIG`.
- **`-s`**: Check all services or a specific service.
- **`-f`**: Check a specific file or directory.
- **`-d`**: Check all files in a specific directory. Use only `-d` to scan the entire `C:\` drive.
- **`-a`**: Check objects in an Active Directory path. Expected format: `"LDAP://CN=username,CN=Users,DC=contoso,DC=local"`.
- **`-recursive`**: Enable recursive mode for Active Directory scans.
- **`-opsec`**: Enable operational security (OPSEC) safe mode.
- **`-v`**: Enable verbose mode for detailed output.

## Examples

### Scan a Specific Registry Hive or Key
```bash
SACL_Scanner.exe -r HKEY_LOCAL_MACHINE
```
```bash
SACL_Scanner.exe -r HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
```

### Scan a Specific Service
```bash
SACL_Scanner.exe -s SomeServiceName
```

### Scan a Specific File
```bash
SACL_Scanner.exe -f "C:\Path\To\File.txt"
```

### Scan an Entire Directory
```bash
SACL_Scanner.exe -d "C:\Path\To\Directory"
```

### Scan an Active Directory Object
```bash
SACL_Scanner.exe -a "LDAP://CN=username,CN=Users,DC=contoso,DC=local"
```

## Notes
- Use the `-recursive` option to recursively scan a container in Active Directory environments.
- OPSEC safe mode minimizes detection risks but might limit scanning capabilities.
- Ensure proper permissions are available to access SACLs on the targeted objects.
- When compiling from source, make sure to set the Runtime Library flag to Multi-threaded (/MT)

