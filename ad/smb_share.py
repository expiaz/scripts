# LSAT LDAP SID translation
from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
import codecs
import ldap3
import ssl
import re

from ldap3.core.exceptions import LDAPKeyError, LDAPAttributeError, LDAPCursorError, LDAPInvalidDnError
from impacket.examples import logger, utils
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException

from impacket.smbconnection import SMBConnection
from impacket.smb3structs import *
from impacket.ldap import ldaptypes
from enum import Enum



CACHED_SIDS = {}
# Universal SIDs
WELL_KNOWN_SIDS = {
    'S-1-0': 'Null Authority',
    'S-1-0-0': 'Nobody',
    'S-1-1': 'World Authority',
    'S-1-1-0': 'Everyone',
    'S-1-2': 'Local Authority',
    'S-1-2-0': 'Local',
    'S-1-2-1': 'Console Logon',
    'S-1-3': 'Creator Authority',
    'S-1-3-0': 'Creator Owner',
    'S-1-3-1': 'Creator Group',
    'S-1-3-2': 'Creator Owner Server',
    'S-1-3-3': 'Creator Group Server',
    'S-1-3-4': 'Owner Rights',
    'S-1-5-80-0': 'All Services',
    'S-1-4': 'Non-unique Authority',
    'S-1-5': 'NT Authority',
    'S-1-5-1': 'Dialup',
    'S-1-5-2': 'Network',
    'S-1-5-3': 'Batch',
    'S-1-5-4': 'Interactive',
    'S-1-5-6': 'Service',
    'S-1-5-7': 'Anonymous',
    'S-1-5-8': 'Proxy',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-12': 'Restricted Code',
    'S-1-5-13': 'Terminal Server Users',
    'S-1-5-14': 'Remote Interactive Logon',
    'S-1-5-15': 'This Organization',
    'S-1-5-17': 'This Organization',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'NT Authority',
    'S-1-5-20': 'NT Authority',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-547': 'Power Users',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
    'S-1-5-64-10': 'NTLM Authentication',
    'S-1-5-64-14': 'SChannel Authentication',
    'S-1-5-64-21': 'Digest Authority',
    'S-1-5-80': 'NT Service',
    'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
    'S-1-16-0': 'Untrusted Mandatory Level',
    'S-1-16-4096': 'Low Mandatory Level',
    'S-1-16-8192': 'Medium Mandatory Level',
    'S-1-16-8448': 'Medium Plus Mandatory Level',
    'S-1-16-12288': 'High Mandatory Level',
    'S-1-16-16384': 'System Mandatory Level',
    'S-1-16-20480': 'Protected Process Mandatory Level',
    'S-1-16-28672': 'Secure Process Mandatory Level',
    'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
    'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
    'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
    'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
    'S-1-5-32-559': 'BUILTIN\Performance Log Users',
    'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
    'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
    'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
    'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
    'S-1-5-32-573': 'BUILTIN\Event Log Readers',
    'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
    'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
    'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
    'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
    'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
    'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
    'S-1-5-32-580': 'BUILTIN\Remote Management Users',
}



"""
SMB SHARE ACL
"""
class SMB_ACL(Enum):
    # Share Access Mode
    # smb.py:124
    SMB_SHARE_COMPAT                 = 0x00
    SMB_SHARE_DENY_EXCL              = 0x10
    SMB_SHARE_DENY_WRITE             = 0x20
    SMB_SHARE_DENY_READEXEC          = 0x30
    SMB_SHARE_DENY_NONE              = 0x40
    SMB_ACCESS_READ                  = 0x00
    SMB_ACCESS_WRITE                 = 0x01
    SMB_ACCESS_READWRITE             = 0x02
    SMB_ACCESS_EXEC                  = 0x03

    # Share Access
    # smb3struct.py:164
    FILE_SHARE_READ         = 0x00000001
    FILE_SHARE_WRITE        = 0x00000002
    FILE_SHARE_DELETE       = 0x00000004



"""
ACCESS_MASK as described in 2.4.3
https://msdn.microsoft.com/en-us/library/cc230294.aspx
"""

# @see https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format
class STANDARD_ACCESS_RIGHTS(Enum):
    GENERIC_READ            = 0x80000000 #0b10000000000000000000000000000000
    GENERIC_WRITE           = 0x40000000 #0b01000000000000000000000000000000
    GENERIC_EXECUTE         = 0x20000000 #0b00100000000000000000000000000000
    GENERIC_ALL             = 0x10000000 #0b00010000000000000000000000000000
    MAXIMUM_ALLOWED         = 0x02000000 #0b00000010000000000000000000000000
    ACCESS_SYSTEM_SECURITY  = 0x01000000 #0b00000001000000000000000000000000
    SYNCHRONIZE             = 0x00100000 #0b00000000000100000000000000000000
    WRITE_OWNER             = 0x00080000 #0b00000000000010000000000000000000
    WRITE_DACL              = 0x00040000 #0b00000000000001000000000000000000
    READ_CONTROL            = 0x00020000 #0b00000000000000100000000000000000
    DELETE                  = 0x00010000 #0b00000000000000010000000000000000

class GENERIC_ACCESS_RIGHTS(Enum):
    GENERIC_READ            = 0x80000000 #0b10000000000000000000000000000000
    GENERIC_WRITE           = 0x40000000 #0b01000000000000000000000000000000
    GENERIC_EXECUTE         = 0x20000000 #0b00100000000000000000000000000000
    GENERIC_ALL             = 0x10000000 #0b00010000000000000000000000000000

# @see https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
class GENERIC_ACCESS_RIGHTS_MAPPING(Enum):
    # FILE_EXECUTE
    # FILE_READ_ATTRIBUTES
    # READ_CONTROL
    # SYNCHRONIZE
    GENERIC_EXECUTE         = 0x20 + 0x80 + 0x00020000 + 0x00100000
    # FILE_READ_ATTRIBUTES
    # FILE_READ_DATA
    # FILE_READ_EA
    # READ_CONTROL
    # SYNCHRONIZE
    GENERIC_READ            = 0x80 + 0x1 + 0x8 + 0x00020000 + 0x00100000
    # FILE_APPEND_DATA
    # FILE_WRITE_ATTRIBUTES
    # FILE_WRITE_DATA
    # FILE_WRITE_EA
    # READ_CONTROL
    # SYNCHRONIZE
    GENERIC_WRITE           = 0x4 + 0x100 + 0x2 + 0x10 + 0x00020000 + 0x00100000
    # MAPPED TO FULL_CONTROL ?
    GENERIC_ALL             = 0x1f01ff

# @see https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783530(v=ws.10)?redirectedfrom=MSDN#permissions-for-files-and-folders
# @see https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-ace?redirectedfrom=MSDN
# @see https://learn.microsoft.com/en-us/archive/msdn-magazine/2008/november/access-control-understanding-windows-file-and-registry-permissions
class OBJECT_SPECIFIC_ACCESS_RIGHTS_FILE(Enum):
    FILE_READ_DATA          = 0x1
    FILE_WRITE_DATA         = 0x2
    FILE_APPEND_DATA        = 0x4
    FILE_READ_EA            = 0x8 # FILE_READ_EXTENDED_ATTRIBUTES
    FILE_WRITE_EA           = 0x10
    FILE_EXECUTE            = 0x20
    FILE_DELETE_CHILD       = 0x40
    FILE_READ_ATTRIBUTES    = 0x80
    FILE_WRITE_ATTRIBUTES   = 0x100

class OBJECT_SPECIFIC_ACCESS_RIGHTS_FOLDER(Enum):
    FILE_LIST_DIRECTORY     = 0x1
    FILE_ADD_FILE           = 0x2
    FILE_ADD_SUBDIRECTORY   = 0x4
    FILE_READ_EA            = 0x8
    FILE_WRITE_EA           = 0x10
    FILE_TRAVERSE           = 0x20
    FILE_DELETE_CHILD       = 0x40
    FILE_READ_ATTRIBUTES    = 0x80
    FILE_WRITE_ATTRIBUTES   = 0x100

class ACE_FLAGS(Enum):
    CONTAINER_INHERIT_ACE       = 0x02
    FAILED_ACCESS_ACE_FLAG      = 0x80
    INHERIT_ONLY_ACE            = 0x08
    INHERITED_ACE               = 0x10
    NO_PROPAGATE_INHERIT_ACE    = 0x04
    OBJECT_INHERIT_ACE          = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG  = 0x40

# Simple permissions enum
# Simple permissions are combinaisons of extended permissions
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783530(v=ws.10)?redirectedfrom=MSDN
# @see https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=net-8.0
class SIMPLE_PERMISSIONS(Enum):
    # FullControl: SYNCHRONIZE,WRITE_OWNER,WRITE_DACL,READ_CONTROL,DELETE,FILE_READ_DATA,FILE_WRITE_DATA,FILE_APPEND_DATA,FILE_READ_EA,FILE_WRITE_EA,FILE_EXECUTE,FILE_DELETE_CHILD,FILE_READ_ATTRIBUTES,FILE_WRITE_ATTRIBUTES
    FullControl = 0xf01ff
    # Modify: SYNCHRONIZE,READ_CONTROL,DELETE,FILE_READ_DATA,FILE_WRITE_DATA,FILE_APPEND_DATA,FILE_READ_EA,FILE_WRITE_EA,FILE_EXECUTE,FILE_READ_ATTRIBUTES,FILE_WRITE_ATTRIBUTES
    Modify = 0x01bf
    # ReadAndExecute: SYNCHRONIZE,READ_CONTROL,FILE_READ_DATA,FILE_READ_EA,FILE_EXECUTE,FILE_READ_ATTRIBUTES
    # ListFolder
    ReadAndExecute = 0x00a9
    # ReadAndWrite: SYNCHRONIZE,READ_CONTROL,FILE_READ_DATA,FILE_WRITE_DATA,FILE_APPEND_DATA,FILE_READ_EA,FILE_WRITE_EA,FILE_READ_ATTRIBUTES,FILE_WRITE_ATTRIBUTES
    ReadAndWrite = 0x019f
    # Read: SYNCHRONIZE,READ_CONTROL,FILE_READ_DATA,FILE_READ_EA,FILE_READ_ATTRIBUTES
    Read = 0x0089
    # Write: FILE_WRITE_DATA,FILE_APPEND_DATA,FILE_WRITE_EA,FILE_WRITE_ATTRIBUTES
    Write = 0x0116


class ShareACL:

    def __init__(self, credentials, smb_conn, ldap_server, ldap_conn, server, share, path):
        # domain, username, password, lmhash, nthash
        self.credentials = credentials
        self.ldap_server = ldap_server
        self.ldap_conn = ldap_conn
        self.smb_conn = smb_conn

        self.tree_id = smb_conn.connectTree(share)

        # for local SID LSAT lookup
        self.lsat_dce = None

        self.server = server
        self.share = share
        self.path = path

        self.domain_root = self.ldap_server.info.other['defaultNamingContext'][0]
        self.domain_sid = self.getDomainSID_LDAP()
        #self.domain_name = self.credentials[0]

        self.ldap_conn.search('CN=Partitions,CN=Configuration,%s' % self.domain_root, '(netbiosname=*)', attributes=['nETBIOSName','dnsRoot'])
        self.domain_netbios = self.ldap_conn.entries[0]['nETBIOSName'].value
        self.domain_name = self.ldap_conn.entries[0]['dnsRoot'].value

        # TODO resolve domain name from LDAP OR LSAT/SMB... locally
        logging.debug('Domain name %s (netbios %s)' % (self.domain_name, self.domain_netbios))
        logging.debug('Domain root: %s' % self.domain_root)
        logging.debug('Domain SID %s' % self.domain_sid)

        # TODO be able to change for which user to resolve rights
        # TODO add -u SID
        # TODO add -u "DN"
        self.ldap_conn.search(self.domain_root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))' % self.credentials[1], attributes=['objectSid'])
        self.rights_for = self.ldap_conn.entries[0]['objectSid'].value
        logging.info('Retrieving ACLs for %s\\%s (SID %s)' % (self.domain_name, self.credentials[1], self.rights_for))

        p = self.lookupGroups(self.rights_for)
        concerned_sids = p.values()
        owner, group, acl = self.getACLforFile(path)
        rights = self.resolveRights(concerned_sids, acl)
        perms, human = self.getAccessMaskPerms(rights)

        logging.info("Owner: %s" % self.resolveSID_LDAP(owner))
        logging.info("Group: %s" % self.resolveSID_LDAP(group))
        logging.info("Rights: %s" % ','.join(human))
        logging.info("Permissions: %s" % ','.join(perms))

        # TODO resolve IP from share

        # for ace in sd['Dacl'].aces:
        #     # TODO ace.hasFlag(ACE.INHERITED_ACE) -> herited from parent -> skip

        #     # ace.hasFlag(ldaptypes.ACCESS_MASK.GENERIC_READ)
        #     # ace['TypeName']
        #     # ace['Ace']
        #     print(ace['TypeName']) # ldaptypes.ACE_TYPES.ACCESS_ALLOWED_ACE || ldaptypes.ACE_TYPES.ACCESS_DENIED_ACE
        #     print(ace['Ace']['Sid'].formatCanonical())
        #     print(translate_sid(ace['Ace']['Sid'].formatCanonical()))
        #     print("ACCESS_MASK %032d" % int(bin(ace['Ace']['Mask']['Mask'])[2:]))
        #     print('FLAGS: %s' % ','.join(parseAceFlags(ace)))
        #     perm, human = parsePerms(ace['Ace']['Mask']['Mask'])
        #     print(','.join(human))
        #     print(','.join(perm))

        #     # for ace in get_aces_for(ace['Ace']['Mask']):
        #     #     print(ace.name)
        #     print()

    def getACLforFile(self, path):
        # TODO resolve if it's a file or a directory
        file_id = self.smb_conn.openFile(self.tree_id, path, desiredAccess=READ_CONTROL | FILE_READ_ATTRIBUTES, creationOption=FILE_NON_DIRECTORY_FILE)
        file_info = self.smb_conn.getSMBServer().queryInfo(self.tree_id, file_id, infoType=SMB2_0_INFO_SECURITY, fileInfoClass=SMB2_SEC_INFO_00, additionalInformation=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION, flags=0)
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(file_info)
        return sd['OwnerSid'].formatCanonical(), sd['GroupSid'].formatCanonical(), sd['Dacl'].aces


    def resolveRights(self, sids, acl):
        allow = 0b0
        deny = 0b0
        for ace in acl:
            sid = ace['Ace']['Sid'].formatCanonical()
            if sid in sids:
                # concerned by the ACE
                access_mask = ace['Ace']['Mask']['Mask']
                p,h = self.getAccessMaskPerms(access_mask)
                if ace['TypeName'] == ldaptypes.ACCESS_DENIED_ACE.__name__:
                    logging.debug('ACE DENIED: %s for %s' % (
                        ','.join(h),
                        self.resolveSID_LDAP(sid)
                    ))
                    deny = deny | access_mask
                elif ace['TypeName'] == ldaptypes.ACCESS_ALLOWED_ACE.__name__:
                    allow = allow | access_mask
                    logging.debug('ACE ALLOWED: %s for %s' % (
                        ','.join(h),
                        self.resolveSID_LDAP(sid)
                    ))
        # these is actually some bugs
        # because the rights shown here does not represent windows reality
        # example: a user denied on folder A but granted on file A/a.txt cannot go nor list
        # the folder A but can still fetch the file A/a.txt if he known its name
        return allow & (deny ^ 0xFFFFFFFF)


    def getDomainSID_LDAP(self):
        self.ldap_conn.search(self.domain_root, '(objectClass=domain)', attributes=['objectSid'])
        try:
            sid = self.ldap_conn.entries[0].objectSid
        except (LDAPAttributeError, LDAPCursorError, IndexError):
            # TODO when not in domain what happens ?!
            return False
        return sid


    def resolveSID_LDAP(self, sid):
        if sid in WELL_KNOWN_SIDS:
            sam = WELL_KNOWN_SIDS[sid]
            logging.debug("SID WELL_KNOWN_SIDS %s -> %s" % (sid, sam))
            return sam
        elif sid in CACHED_SIDS:
            sam = CACHED_SIDS[sid]
            logging.debug("SID CACHED_SIDS %s -> %s" % (sid, sam))
            return sam
        else:
            # lookup only domain SIDs to avoid unnecessary noise
            # if not sid.startswith(self.domain_sid):
            #   return self.resolveSID_LSAT(sid)
            self.ldap_conn.search(self.domain_root, '(objectSid=%s)' % sid, attributes=['samaccountname'])
            try:
                dn = self.ldap_conn.entries[0].entry_dn
                sam = self.ldap_conn.entries[0]['samaccountname']
                CACHED_SIDS[sid] = "%s\\%s" % (self.domain_name, sam)
                logging.debug("LDAP SID lookup %s -> %s" % (sid, CACHED_SIDS[sid]))
                return sam
            except IndexError:
                logging.debug('SID not found in LDAP: %s' % sid)
                logging.debug('Trying LSAT resolve on %s' % self.server)
                return self.resolveSID_LSAT(sid)


    def resolveSID_LSAT(self, sid):
        if self.lsat_dce == None:
            logging.debug('Opening DCERPC LSAT on %s' % self.server)
            # TODO add ports 139
            rpctransport = transport.DCERPCTransportFactory('ncacn_np:%s[\pipe\lsarpc]' % self.server)
            rpctransport.set_dport(445)
            rpctransport.setRemoteHost(self.server)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.credentials[1], self.credentials[2], self.credentials[0], self.credentials[3], self.credentials[4])

            self.lsat_dce = rpctransport.get_dce_rpc()
            self.lsat_dce.connect()
            self.lsat_dce.bind(lsat.MSRPC_UUID_LSAT)
        
        resp = lsad.hLsarOpenPolicy2(self.lsat_dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        # # domain SID lookup
        # resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
        # domainSid =  resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
        # print(domainSid)
        # # local SID looukp
        # resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        # localSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        # print(localSid)

        try:
            resp = lsat.hLsarLookupSids(self.lsat_dce, policyHandle, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
            if str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                resp = e.get_packet()
            else:
                # SID not found ?!
                logging.debug('LSAT SID lookup error: %s' % sid)
                return sid
        
        for n, item in enumerate(resp['TranslatedNames']['Names']):
            if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                CACHED_SIDS[sid] = "%s\\%s" % (resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'])
                logging.debug('LSAT SID lookup: %s -> %s' % (sid, CACHED_SIDS[sid]))
                return CACHED_SIDS[sid]
                #return "%s\\%s (%s) (%s)" % (resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'],SID_NAME_USE.enumItems(item['Use']).name, sid)
            else:
                logging.debug('SID not found in LSAT: %s' % sid)
                return sid


    # find groups
    # @see https://github.com/franc-pentest/ldeep/blob/master/ldeep/__main__.py#L947
    # @see https://www.gabescode.com/active-directory/2018/06/08/finding-all-of-a-users-groups.html
    # @see recursive fetch LDAP_MATCHING_RULE_IN_CHAIN member:1.2.840.113556.1.4.1941:=
    # lookup groups given an object SID
    # based on the memberOf attribute
    # and the primaryGroupId attribute
    # TODO add external trusted domains (hard bro)
    # @param groups dict DN -> SID: because memberOf[] attribute store groups DN, facilitates resolving the SID for groups
    def lookupGroups(self, sid, already_treated={}):
        if sid in already_treated.values():
            return already_treated

        self.ldap_conn.search(self.domain_root, '(objectSid=%s)' % sid, attributes=['distinguishedName', 'primaryGroupId', 'memberOf', 'sAMAccountName'])
        # add to resolved objects
        try:
            dn = self.ldap_conn.entries[0]['distinguishedName'].value
            already_treated[dn] = sid
            # TODO add to CACHED_SIDS
            # TODO resolve domain + sAMAccountName
            # CACHED_SIDS[sid] = "%s\\%s" % (self.domain_name, self.ldap_conn.entries[0]['sAMAccountName'].value)
        except:
            return already_treated

        try:
            groups = self.ldap_conn.entries[0]['memberOf'].values
        except:
            groups = []

        try:
            primaryGroupId = self.ldap_conn.entries[0]['primaryGroupId'].value
        except:
            primaryGroupId = None

        # resolve primary group
        if primaryGroupId != None:
            self.lookupGroups('%s-%d' % (self.domain_sid, self.ldap_conn.entries[0]['primaryGroupId'].value), already_treated)

        for group_dn in groups:
            if group_dn not in already_treated:
                self.ldap_conn.search(group_dn, '(objectClass=*)', attributes=['objectSid'])
                self.lookupGroups(self.ldap_conn.entries[0]['objectSid'].value, already_treated)


        return already_treated



    def getAceFlags(self, ace):
        flags = []
        for FLAG in ACE_FLAGS:
            if ace.hasFlag(FLAG.value):
                flags.append(FLAG.name)
        return flags

    # Parses an access mask to extract the different values from a simple permission
    # https://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
    #   - fsr : the access mask to parse
    def getAccessMaskPerms(self, fsr):
        _perm = []
        _human = []

        for PERM in GENERIC_ACCESS_RIGHTS:
            if (fsr & PERM.value) == PERM.value:
                logging.debug('parseAccessMask adding %s' % (PERM.name))
                fsr = fsr | GENERIC_ACCESS_RIGHTS_MAPPING[PERM.name].value

        for PERM in STANDARD_ACCESS_RIGHTS:
            if fsr & PERM.value:
                _perm.append(PERM.name)
        
        for PERM in OBJECT_SPECIFIC_ACCESS_RIGHTS_FOLDER:
            if fsr & PERM.value:
                _perm.append(PERM.name)

        for PERM in SIMPLE_PERMISSIONS:
            if (fsr & PERM.value) == PERM.value:
                _human.append(PERM.name)
                fsr = fsr & (not PERM.value)

        return _perm, _human





def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if args.dc_ip is not None:
        connect_to = args.dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if args.k:
        ldap_conn = ldap3.Connection(ldap_server)
        ldap_conn.bind()
        ldap3_kerberos_login(ldap_conn, target, username, password, domain, lmhash, nthash, args.aesKey, kdcHost=args.dc_ip)
    elif args.hashes is not None:
        ldap_conn = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_conn = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_conn


def init_ldap_conn(args, domain, username, password, lmhash, nthash):
    if args.k:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain

    if args.use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, args, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, args, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, args, domain, username, password, lmhash, nthash)

def init_smb_conn(args, server, domain, username, password, lmhash, nthash):
    smbClient = SMBConnection(server, server, sess_port=445)
    if args.k is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip )
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    return smbClient

share_regex = re.compile(r"^(?://)?([^/]+)/([^/]+)(/.*)?$")
def parse_target(target):
    server, share, path = share_regex.match(target).groups('')
    if path == '':
        path = '/'
    return server, share, path


def parse_identity(args):
    domain, username, password = utils.parse_credentials(args.identity)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass
        logging.info("No credentials supplied, supply password")
        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if len(nthash) > 0 and lmhash == "":
        lmhash = "aad3b435b51404eeaad3b435b51404ee"

    return domain, username, password, lmhash, nthash


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Impacket script to show an SMB file DACL for a given principal.')
    parser.add_argument('identity', action='store', help='domain/username[:password]')
    parser.add_argument('-t', action='store', dest='target', required=True, help='//server[/share[/path/to/file.txt]]')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication & connection')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    args = parse_args()
    logger.init()
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    print(version.BANNER)
    server, share, path = parse_target(args.target)
    domain, username, password, lmhash, nthash = parse_identity(args)
    
    ldap_server, ldap_conn = init_ldap_conn(args, domain, username, password, lmhash, nthash)
    smb_conn = init_smb_conn(args, server, domain, username, password, lmhash, nthash)
    shareacl = ShareACL(
        (domain, username, password, lmhash, nthash),
        smb_conn,
        ldap_server,
        ldap_conn,
        server,
        share,
        path
    )


if __name__ == '__main__':
    main()






# TODO check SHARE ACL over NTFS ACL (share folder & under)
# if a perm is explicitely denied for a user in share ACL

# user READ denied in share ACL -> can't access share even is NTFS folder shares has access for the user
# user CHANGE denied in share ACL -> can't upload files nor delete files
# rights are a combination of the 2 SHARE AND NTFS rights => most restrictives kept


# TODO check ACL exclusion (Write) and ACL permission
# to see if a user w/ write denied can still read/exec if he has explicit or inherited rights
# => yes


# TODO groups in groups ACL
# e.g. group A has write access and group B is in group A -> group B write access ?!

# parent folder A denies group G but allows user U of group G
# TODO deny folder A but allow file A/a.txt
# jdoe in is group G
# folder test/A denies read G but test/A/a.txt allows jdoe
# => jdoe CANT list folder A yet CAN fetch A/a.txt directly even if read is denied from its group

# TODO owner / group rights default ACLs => ??








def print_perms_perms():
    for PERM in SIMPLE_PERMISSIONS:
        ps = []
        for p in GENERIC_ACCESS_RIGHTS_MAPPING:
            if (PERM.value & p.value) == p.value:
                ps.append(p.name)
        for p in STANDARD_ACCESS_RIGHTS:
            if (PERM.value & p.value) == p.value:
                ps.append(p.name)
        for p in OBJECT_SPECIFIC_ACCESS_RIGHTS_FILE:
            if (PERM.value & p.value) == p.value:
                ps.append(p.name)
        print("%s: %s" % (PERM.name,','.join(ps)))


