# Files

## Queries
**Filenames with multiple spaces**
Threat actors can add many spaces to a filename to make it artificially long so that the extension becomes invisible in Windows.
> `filename contains '  ' || attachment contains '  '`

**Filenames with multiple extensions**
Attackers can give files double extensions to make them look legitimate when by default Windows hides the last extensions (such as `.pdf.exe` would look like `.pdf` to the user).
> `extension contains '.' && extension != 'min.css','exe.json','cab.json','tar.gz','tar.bz2','tar.xz','html.erb','md.html','user.js','min.js','spec.js','dll.config' && not(extension ends 'gz')`

**Potential files containing passwords**
Users may store their passwords in files instead of password managers, and often save them using obvious filename. Specially look over SMB traffic (accessible over remote shares).
> `filename contains 'password' && filename ends 'txt','xlsx','xls'`

**Transfer of private key files**
Look for potentially critical certificates, such as root, private, ...
> `filename ends '.key','.pem','.p12','.pfx','.der'`

**Base64 hidden in fake certificates**
In some cases, have seen threat actors trasfering fake .cer files, which when based64 decoded show hidden data/beacons/commands.
> `filename ends '.cer' && ioc = 'possible base64 window shell'`

**Filenames with common ransomware extensions**
File extensions commonly used by ransomware.
> `extension ends 'cerber', 'crypt', 'crypt1', 'crypto', 'enc', 'encrypted', 'locked', 'locky', 'odin', 'ryuk', 'wannacry', 'wncry'`
