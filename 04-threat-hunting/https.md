# HTTPS

**Outbound connections to self-signed certificates**
Review the domains returned and check for uncommon/untrusted ones.
> `direction = 'outbound' && analysis.service = 'ssl certificate self-signed'`

**Outbound connections to recently generated certificates**
Review the domains returned and check for uncommon/untrusted ones.
> `direction = 'outbound' && analysis.service = ''certificate issued within last day', 'certificate issued within last month', 'certificate issued within last week''`

**Outbound connections to expired certificates**
Review the domains returned and check for uncommon/untrusted ones.
> `direction = 'outbound' && analysis.service = 'certificate expired'`

**Outbound connections to certificates with longer than usual expiry**
Review the domains returned and check for uncommon/untrusted ones.
> `direction = 'outbound' && analysis.service = 'certificate long expiration'`

**TLS using non-standard ports**
> `service = 443 && tcp.dstport != 443 && direction = 'outbound'`

**Encrypted outbound session over 443 but not TLS/SSL**
Exclude `entropy` if not indexed.
> `direction = 'outbound' && tcp.dstport = 443 && service != 443 && entropy > 7000 && tcp.flags.desc = 'syn' && streams = 2`
