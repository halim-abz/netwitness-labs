# HTTP

**Suspicious Office User-Agent**
User agent strings from inexistent versions of Word and Excel downloading DLL files such as `saw.dll`. There is no legitimate version of Word/Excel 2014.
> `client contains 'excel','word','office' && client contains '2014'`

Widen to anything from office
> `direction = 'outbound' && client contains 'excel','word','office'`

**Find all non-standard HTTP methods**
> `service = 80 && ~(action = 'get','post','head','options','put','delete','patch')`

**Or focus on particularly suspicious methods**
For example, CONNECT can be indicative of a user tunnelling traffic via a Proxy server. Threat actors can also use Proxy servers in a lateral direction to overcome segmentation. Look for proxy traffic, excluding approved internal proxy servers.
> `service = 80 && action = 'connect','trace','profind','debug'`

**Find unusually short user agents (often automation tools)**
> `length(client) < 10`

**Check for user agents impersonating common tools with slight modifications**
> `client regex '(?i)goo[o]+gle|chrom[^e]|mozilla\/[^5]'`

**Look for known malicious user agents**
> `client contains 'zgrab','gobuster','hydra','arachni','BFAC','brutus','cgichk','core-project','crimscanner','datacha0s','dirbuster','domino hunter','dotdotpwn','FHScan','floodgate','get-minimal','gootkit','grendel-scan','inspath','internet ninja','jaascois','zmeu','masscan','metis','morfeus fucking scanner','n-stealth','nsauditor','pmafind','security scan','springenwerk','forest lobster','toata dragostea','vega','voideye','webshag','webvulnscan','whcc','Havij','absinthe','bsqlbf','mysqloit','pangolin','sql power injector','sqlmap','sqlninja','uil2pn','nasl','advanced email extractor','nessus','burp','bilbo','cisco-torch','commix','grabber','grendel','nmap','netsparker','nikto','openvas','paros','prog.customcrawler','qualys','s.t.a.l.k.e.r.','this is an exploit','w3af','webbandit','webinspect','whatweb','wordpress hash grabber','xmlrpc exploit','WPScan','metasploit','kali','powersploit'`

**Look for suspicious user agents**
> `client contains 'Moxilla','test','sample','pwn','mozila','user-agent','exploit','hack' || client begins 'asd'`

**Look for outbound connections using common CLI tools/scripts**
> `direction = 'outbound' && service = 80 && client contains 'curl', 'wget', 'python', 'powershell', 'microsoft bits', 'certutil'`

**PowerShell initiating network connections**
> `direction = 'outbound' && client contains 'WindowsPowerShell'`

**Check outbound connections direct to IP**
> `direction = 'outbound' && service = 80 && analysis.service = 'http direct to ip request'`

**Look for HTTP POST requests without GET**
> `service = 80 && action = 'post' && action != 'get'`
> `service = 80 && action = 'post' && action != 'get' && referer !exists`

**Connections to typical WebShell filenames**
> `direction = 'inbound' && service = 80 && filename = 'sh.php','w.php','wso.php','c99.php','c99shell.php','shell.php','cmd.php','cmd.aspx','b374k.php','aspxspy.aspx','r57.php','r57shell.php','c.aspx','c.php','caidao.php'`

**Connections with typical WebShell query parameters**
> `direction = 'inbound' && service = 80 && query contains 'z0=' && query contains 'z1=' && query contains 'z2='`

**Find potential XSS attempts**
>`service = 80 && query contains '<script>','<?php','javascript:','alert(','onerror=','onload='`
