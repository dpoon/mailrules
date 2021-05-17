#!/usr/bin/python3

# Copyright 2020-2021 Dara Poon and the University of British Columbia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
from collections import namedtuple, OrderedDict
from glob import glob
import os
import pwd
import re
import sys
try:
    from mailrules.custom import post_process
except ImportError:
    post_process = lambda script, conversion_context: script
import mailrules
import mailrules.forward_to_sieve
import mailrules.procmailrc
import mailrules.proc_to_sieve
import mailrules.sieve

def parse_args(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-u', '--user',
        type=str,
        help="username whose configuration to convert",
    )
    parser.add_argument('-i', '--inbox',
        type=str,
        help="path to the user's inbox, relative to user's home directory"
             " (defaults to /var/mail/$USER)",
    )
    parser.add_argument('-d', '--domain',
        type=str,
        help="email domain (for resolving unqualified local addresses)",
    )
    parser.add_argument('-p', '--provenance-comments',
        action='store_true',
        help='output comments about the source filenames and their modification times',
    )
    return parser.parse_args(args)

def error(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)

def conversion_context(opts):
    procmail_context = mailrules.proc_to_sieve.ProcmailContext(
        user=opts.user,
        email_domain=opts.domain,
        env={
            'LOGNAME': opts.user or os.getenv('LOGNAME'),
            'HOME': lambda c: c.directory,
            'MAILDIR': lambda c: c.directory,
            'DEFAULT': lambda c: os.path.abspath(c.resolve_path(
                opts.inbox or
                os.path.join('/var/mail', opts.user or os.getenv('LOGNAME'))
            )),
            'ORGMAIL': os.path.join('/var/mail', opts.user or os.getenv('LOGNAME')),
            'PATH': '/usr/local/bin:/usr/bin:/bin',
        },
        provenance_comments=opts.provenance_comments,
    )

    if not os.path.isdir(procmail_context.resolve_path('')):
        error("No home directory for user {0}".format(opts.user))
    procmailrc_path = procmail_context.resolve_path('.procmailrc')
    if not os.path.isfile(procmailrc_path):
        procmailrc_path = None

    forward_paths = list(
        filter(
            lambda path: re.fullmatch(r'\.forward\+[A-Za-z0-9_]+', os.path.basename(path)),
            glob(procmail_context.resolve_path('.forward+*'))
        )
    ) + glob(procmail_context.resolve_path('.forward'))

    return namedtuple('ConversionContext',
            'forward_paths procmailrc_path procmail_context')(
        {re.sub(r'.*/.forward\+?', '', path): path for path in forward_paths},
        procmailrc_path,
        procmail_context
    )

def sieve_commands(conversion_context):
    procmail_context = conversion_context.procmail_context
    ext_forwards = OrderedDict(mailrules.forward_to_sieve.ForwardFiles(
        conversion_context.forward_paths,
        procmail_context
    ))
    for ext in (e for e in ext_forwards if e):
        _, sieve_commands = ext_forwards[ext]
        yield from sieve_commands
    if '' in ext_forwards:
        keep_copy, sieve_commands = ext_forwards['']
        yield from sieve_commands
        if not keep_copy:
            return
    if conversion_context.procmailrc_path:
        yield from mailrules.proc_to_sieve.Procmailrc(
            conversion_context.procmailrc_path,
            procmail_context
        )

def main():
    conv = conversion_context(parse_args())
    out = mailrules.sieve.Script()
    try:
        for cmd in sieve_commands(conv):
            out.add_command(cmd)
        out = post_process(out, conv)
        sieve_script_text = str(out)
        if sieve_script_text:
            print(sieve_script_text, end='\r\n')

        sys.exit(1 if mailrules.proc_to_sieve.FIXME.instances else 0)
    except mailrules.UnresolvedLocalEmailAddressException:
        error("error: the following arguments are required: -d/--domain")


if __name__ == '__main__':
    main()
