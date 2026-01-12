# SMB

## Things to look for
- Review failed logins (bruteforce, password spraying, ...)
- Review file transfers (what files are being transferred, lots of files copied from same user, copy of same executable to many machines)
- User accounts used to login (admin, service accounts, computer accounts), usually under `ad.username.dst`
- Weak passwords

## Queries

**Failed logins over SMB**
> `service = 139 && error = 'logon failure'`

**File written over an SMB session**
Look for sessions with many files written.
> `service = 139 && action = 'write'`

**Failed access to network share**
Look for multiple denied access attempts from the same source.
> `service = 139 && error 'access denied'`

**Potential remote execution using PSExec**
> `service = 139 && boc = 'create remote service' && boc = 'start remote service'`

**Potential remote execution using WMI**
> `service = 139 && boc = 'remote wmi activity' && action = 'ExecMethod'`

**General suspicious remote actions**
> `service = 139 && boc = 'shut down remote system', 'create remote service', 'start remote service', 'create remote task'`

**Remotely add a user to a domain group**
> `service = 139 && boc = 'add user to domain group'`

**Executable copied to remote share**
Look for the same file being copied/replicated to multiple destination
> `service = 139 && action = 'create' && action = 'write' && directory contains 'c$' && filetype = 'windows executable','windows_executable','windows installer','windows installer msi','windows_dll','windows dll','cab','x86 pe','x86_pe','x64 pe'`
