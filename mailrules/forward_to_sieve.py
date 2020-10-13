# Copyright 2020 Dara Poon and the University of British Columbia

from datetime import datetime
import dateutil.tz
from itertools import chain
import os
import re
import mailrules.proc_to_sieve as proc_to_sieve
import mailrules.sieve as sieve

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

def ForwardFiles(ext_file_map, context, provenance_comments=False):
    for extension, forward_path in reversed(list(ext_file_map.items())):
        yield from ForwardFile(
            forward_path,
            extension,
            context,
            provenance_comments
        )
        context = proc_to_sieve.ProcmailContext(parent=context, chain_type='else')

def mailbox_name(s, context):
    s = re.sub('^~/', context.initial.getenv('HOME') + '/', s)
    if s.startswith(context.initial.getenv('MAILDIR')):
        if context.initial.getenv('MAILDIR') + '/' == s:
            return 'inbox'
        else:
            return re.sub('^' + re.escape(context.initial.getenv('MAILDIR')) + '/\.?(.*?)/?$', r'\g<1>', s)
    return None


def ForwardFile(path, extension, context, provenance_comments=False):
    def interpret(expansion):
        keep_copy = '\\' + context.initial.getenv('LOGNAME') in expansion
        for dest in expansion:
            if mailbox_name(dest, context):
                yield sieve.FileintoAction(mailbox_name(dest, context), copy=keep_copy)
            elif dest.startswith('|'):
                yield proc_to_sieve.FIXME(dest) # Pipes not supported
            elif dest.startswith(':include:'):
                yield sieve.FIXME(dest) # Pipes not supported
            elif dest == '\\' + context.initial.getenv('LOGNAME'):
                pass
            else:
                yield sieve.RedirectAction(dest, copy=keep_copy)
        if not keep_copy:
            yield sieve.StopControl()

    with open(path) as f:
        contents = ' '.join(
            line.strip()
            for line in f
            if not line.startswith('#')
        )
        if not provenance_comments:
            provenance = []
        else:
            mtime = os.fstat(f.fileno()).st_mtime
            tz = dateutil.tz.gettz(os.getenv('TZ'))
            provenance = [
                sieve.Comment('Converted from {} ({})'.format(
                    path,
                    datetime.fromtimestamp(mtime, tz=dateutil.tz.gettz()).strftime('%Y-%m-%d %H:%M:%S %z')
                ))
            ]

    expansion = re.findall(r'(?:"(?:\\.|[^"])*"|[^,\s])+', contents)
    test = sieve.EnvelopeTest('to', extension, address_part=':detail') if extension else sieve.TrueTest()


    yield from context.context_chain(
        test,
        provenance + list(interpret(expansion))
    )
