# DNS

## Things to look for
- Long domain names that look dynamically generated
- Domain name with many layers of long and base64 looking subdomains - can be indicative of a threat actor exfiltrating data using the subdomains to a domain he controls
- Many DNS requests for the same domain but many different subdomains - same as above, exfiltration over subdomains
- Many failed DNS requests from the same source to different unique domains - can be indicative of DGA activity, where the malware iterates through multiple dynamically generated domains until one is reachable

## Queries

**Suspiciously long hostnames**
> `service = 53,80 && length(domain) > 60 && direction = 'outbound'`

**6 or more subdomains**
> `alias.host regex '([\\\\.].*){6,}'`

**Large Subdomains**
> `alias.host regex '([^\\\\.]){30,}.'`

**non-alphanumerical domain**
> `service = 80,443,53 && alias.host regex '[^a-zA-Z0-9.\\\-_]'`

**Mixed upper and lower case domains for outbound traffic**
Humans don't tend to type domain names with both upper and lower case (expect for the 1st letter due to autocorrect on mobile phones).
> `alias.host regex '(?-i)[a-z][A-Z]' && (direction='outbound' || service = 53)`

**Failed DNS Resolutions**
Look for many failed DNS resolutions to many different unique domains from the same source IP (could be related to DGA attack). Exclude local domains.
> `service = 53 && dns_querytype = 'a record' && error = 'no name' && tld != 'local','lan'`
