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

from datetime import datetime, timezone
from email.utils import getaddresses
from itertools import chain
import os
import re
import mailrules.proc_to_sieve as proc_to_sieve
from mailrules.shellcmd import parse_cmdline, ShellCommandException
import mailrules.sieve as sieve

try:
    import dateutil.tz
    tz = dateutil.tz.gettz(os.getenv('TZ'))
except ImportError:
    tz = timezone.utc

"""
       Users  can  control  delivery  of  their  own  mail  by  setting up .forward files in their home directory.  Lines in per-user .forward files have the same syntax as the
       right-hand side of aliases(5) entries.

       The format of the alias database input file is as follows:

       ·      An alias definition has the form

                   name: value1, value2, ...

       ·      Empty lines and whitespace-only lines are ignored, as are lines whose first non-whitespace character is a `#'.

       ·      A logical line starts with non-whitespace text. A line that starts with whitespace continues a logical line.

       The name is a local address (no domain part).  Use double quotes when the name contains any special characters such as whitespace, `#', `:', or `@'. The name  is  folded
       to lowercase, in order to make database lookups case insensitive.

       In addition, when an alias exists for owner-name, delivery diagnostics are directed to that address, instead of to the originator of the message.  This is typically used
       to direct delivery errors to the maintainer of a mailing list, who is in a better position to deal with mailing list delivery problems than the originator of  the  unde‐
       livered mail.

       The value contains one or more of the following:

       address
              Mail is forwarded to address, which is compatible with the RFC 822 standard.

       /file/name
              Mail  is  appended  to  /file/name.  See local(8) for details of delivery to file.  Delivery is not limited to regular files.  For example, to dispose of unwanted
              mail, deflect it to /dev/null.

       |command
              Mail is piped into command. Commands that contain special characters, such as whitespace, should be enclosed between double quotes. See local(8)  for  details  of
              delivery to command.

              When the command fails, a limited amount of command output is mailed back to the sender.  The file /usr/include/sysexits.h defines the expected exit status codes.
              For example, use "|exit 67" to simulate a "user unknown" error, and "|exit 0" to implement an expensive black hole.

       :include:/file/name
              Mail is sent to the destinations listed in the named file.  Lines in :include: files have the same syntax as the right-hand side of alias entries.

              A destination can be any destination that is described in this manual page. However, delivery to "|command" and /file/name is disallowed by  default.  To  enable,
              edit the allow_mail_to_commands and allow_mail_to_files configuration parameters.
"""

def ForwardFiles(ext_file_map, context):
    for extension, forward_path in ext_file_map.items():
        yield extension, ForwardFile(
            forward_path,
            extension,
            context
        )
        context = proc_to_sieve.ProcmailContext(parent=context, chain_type=None)

def mailbox_name(s, context):
    return re.sub(
        '^' + re.escape(context.initial.getenv('DEFAULT')) + '/+(.*?)/*$',
        r'INBOX\g<1>',
        context.resolve_path(s)
    ) if '/' in s else None

def ForwardFile(path, extension, context):
    def is_to_myself(dest):
        me = context.initial.getenv('LOGNAME')
        return dest in (me, '\\' + me, me + '@' + context.initial.email_domain)
    def interpret(destinations, keep_copy):
        for dest in destinations:
            if is_to_myself(dest):
                pass
            elif dest == os.path.devnull:
                pass
            elif dest.startswith('|'):
                try:
                    yield from parse_cmdline(context, re.sub(r'^\|', '', dest))
                except ShellCommandException as e:
                    yield proc_to_sieve.FIXME('{}: ({})'.format(str(e), dest))
            elif dest.startswith(':include:'):
                yield proc_to_sieve.FIXME(dest) # Includes not supported
            elif mailbox_name(dest, context):
                yield sieve.FileintoAction(mailbox_name(dest, context), copy=keep_copy)
            else:
                yield sieve.RedirectAction(context.resolve_email_address(dest), copy=keep_copy)
        if not keep_copy:
            yield sieve.StopControl()

    try:
        with open(path) as f:
            if not context.emit_provenance_comments:
                provenance = []
            else:
                mtime = os.fstat(f.fileno()).st_mtime
                tz = dateutil.tz.gettz(os.getenv('TZ'))
                provenance = [
                    sieve.Comment('Converted from {} ({})'.format(
                        path,
                        datetime.fromtimestamp(mtime, tz).strftime('%Y-%m-%d %H:%M:%S %z')
                    ))
                ]

            contents = [line.rstrip() for line in f if not line.startswith('#')]
    except OSError as e:
        return True, [sieve.Comment("Error reading {} ({})".format(path, e))]

    # Fixup for not-quite-proper input that Postfix's local(8) accepts but
    # email.utils.getaddresses() wouldn't: treat
    #    | "/usr/bin/procmail"
    # as
    #    "|/usr/bin/procmail"
    contents = [re.sub(r'\|\s*"([^"]*)"', r'"|\g<1>"', line) for line in contents]

    destinations = [dest for _, dest in getaddresses(contents) if dest]
    keep_copy = (not destinations) or any(is_to_myself(e) for e in destinations)
    test = sieve.EnvelopeTest('to', extension, address_part=':detail') if extension else sieve.TrueTest()

    return keep_copy, context.context_chain(
        test,
        provenance + list(interpret(destinations, keep_copy))
    )
