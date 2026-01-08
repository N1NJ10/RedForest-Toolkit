#!/usr/bin/env python3
import argparse
import ssl
import time
from ldap3 import Server, Connection, NTLM, SASL, GSSAPI, ALL, SUBTREE, Tls
from ldap3.core.exceptions import LDAPException
from dateutil.relativedelta import relativedelta as rd

parser = argparse.ArgumentParser(description='Dump Fine Grained Password Policies')
parser.add_argument('-u', '--username', help='LDAP username', required=False)
parser.add_argument('-p', '--password', help='LDAP password (or hash)', required=False)
parser.add_argument('-l', '--ldapserver', help='LDAP server (hostname or IP)', required=True)
parser.add_argument('-d', '--domain', help='AD domain (e.g. corp.local)', required=True)
parser.add_argument('--use-ldaps', help='Use LDAPS (SSL/TLS)', action='store_true')
parser.add_argument('--kerberos', help='Use Kerberos (GSSAPI)', action='store_true')
parser.add_argument('--port', help='Custom port (default 389 or 636)', type=int)

def base_creator(domain):
    return ','.join(f"DC={dc}" for dc in domain.split('.'))

def clock(nano):
    sec = int(abs(nano / 10_000_000))
    fmt = '{0.days} days {0.hours} hours {0.minutes} minutes {0.seconds} seconds'
    return fmt.format(rd(seconds=sec))

def connect(args):
    use_ssl = args.use_ldaps
    port = args.port or (636 if use_ssl else 389)

    tls_config = Tls(validate=ssl.CERT_NONE)
    server = Server(args.ldapserver, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls_config if use_ssl else None)

    try:
        if args.kerberos:
            print("[*] Using Kerberos authentication (GSSAPI)...")
            conn = Connection(
                server,
                authentication=SASL,
                sasl_mechanism=GSSAPI,
                auto_bind=True
            )
        else:
            if not args.username or not args.password:
                raise ValueError("Username and password required for NTLM authentication.")
            user = f"{args.domain}\\{args.username}"
            print(f"[*] Using NTLM authentication for user {user}...")
            conn = Connection(
                server,
                user=user,
                password=args.password,
                authentication=NTLM,
                auto_bind=True
            )
        print("[+] LDAP bind successful.\n")
        return conn
    except LDAPException as e:
        print(f"[-] LDAP bind failed: {e}")
        exit(1)

def enumerate_fgpp(conn, domain):
    base = base_creator(domain)
    fgpp_base = f"CN=Password Settings Container,CN=System,{base}"

    print("[*] Searching for Fine Grained Password Policies...\n")
    conn.search(search_base=fgpp_base, search_filter='(objectClass=msDS-PasswordSettings)', attributes=['*'])

    if not conn.entries:
        print("[-] No FGPP policies found.")
        return

    print(f"[+] {len(conn.entries)} FGPP policies found.\n")

    for entry in conn.entries:
        print("Policy Name:", entry['name'])
        if 'description' in entry and entry['description']:
            print("Description:", entry['description'])
        print("Minimum Password Length:", entry['msds-minimumpasswordlength'])
        print("Password History Length:", entry['msds-passwordhistorylength'])
        print("Lockout Threshold:", entry['msds-lockoutthreshold'])
        print("Observation Window:", clock(int(entry['msds-lockoutobservationwindow'].value)))
        print("Lockout Duration:", clock(int(entry['msds-lockoutduration'].value)))
        print("Complexity Enabled:", entry['msds-passwordcomplexityenabled'])
        print("Minimum Password Age:", clock(int(entry['msds-minimumpasswordage'].value)))
        print("Maximum Password Age:", clock(int(entry['msds-maximumpasswordage'].value)))
        print("Reversible Encryption:", entry['msds-passwordreversibleencryptionenabled'])
        print("Precedence (lower = higher priority):", entry['msds-passwordsettingsprecedence'])

        for target in entry['msds-psoappliesto']:
            print("Policy Applies to:", target)
        print("")

def enumerate_applied_objects(conn, domain):
    print("[*] Enumerating objects with FGPP applied...\n")
    base = base_creator(domain)
    conn.search(search_base=base, search_filter='(msDS-PSOApplied=*)',
                attributes=['DistinguishedName', 'msDS-PSOApplied'])

    if not conn.entries:
        print("[-] No applied objects found.")
        return

    for entry in conn.entries:
        print("Object:", entry['DistinguishedName'])
        print("Applied Policy:", entry['msDS-PSOApplied'])
        print("")

def main():
    args = parser.parse_args()
    conn = connect(args)
    enumerate_fgpp(conn, args.domain)
    enumerate_applied_objects(conn, args.domain)

if __name__ == "__main__":
    main()
