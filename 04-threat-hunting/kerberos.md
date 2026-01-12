# Kerberos

## Things to look for
- The username logging in is under `ad.username.src`
- Look for patterns of bruteforcing, password spraying, ...
- Look for locked accounts and failed logins
- Look for cipher downgrade attacks

**Kerberos Common Errors**

| Error                  | Comment                                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------------------------- |
| KRB_AP_ERR_TKT_EXPIRED | Ticket has expired (can be normal and common, can also be an attacker trying to use an expired ticket)          |
| KRB_AP_ERR_TKT_NYV     | Ticket not yet valid (usually means clocks are not synchronized)                                                |
| KRB_AP_ERR_NO_TGT      | User requesting a service ticket without first having a TGT ticket (could be bypassing authentication)          |
| KDC_ERR_PREAUTH_FAILED | Failed authentication, small numbers are common, large volume could be a bruteforce or password spraying attack |
| KDC_ERR_CPW_EXP        | Expired password, can be expected in environments where password expiration is enabled                          |

## Queries

**Review Kerberos Errors**
See above table for some available errors.
> `service =88 && error exists`

**Kerberos authentication attempt with disabled account**
> `error = 'kdc err client revoked'`

**Kerberos with weak encryption algorithm**
Can potentially be a Kerberos cipher downgrade attack.
> `service = 88 && crypto begins 'rc4','des'`
