#!/usr/bin/env python
import argparse
import re
import sys

from mysmb import MYSMB

'''
Script for
- check target if MS17-010 is patched or not.
- find accessible named pipe
'''


def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store',
                        help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('connection')
    group.add_argument('--target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If ommited it will use whatever was specified as '
                            'target. This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('--port', nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()
    return options


def parse_domain_and_credentials(options):
    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
                options.target).groups('')

    # In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey \
                is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName
    return domain, username, password, remoteName


def scan():
    delimiter = '*' * 30
    options = get_arguments()

    domain, username, password, remoteName = parse_domain_and_credentials(options)

    print('[*] Logging in...')
    connection = MYSMB(options.target_ip, int(options.port))
    connection.login_or_fail(username, password)
    print(delimiter)

    tid = connection.tree_connect_andx('\\\\' + options.target_ip + '\\' + 'IPC$')
    connection.set_default_tid(tid)

    print('[*] Checking for the MS17-010')
    connection.check_ms17_010()
    print(delimiter)

    print('[*] Checking for the accessible pipes')
    connection.find_named_pipe(firstOnly=False)
    print(delimiter)

    print('[*] MS17-010 scan has been finished, disconnecting...')
    connection.disconnect_tree(tid)
    connection.logoff()
    connection.get_socket().close()

    print('[*] Done')


scan()
