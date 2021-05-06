# Copyright 2021 Dara Poon and the University of British Columbia

from argparse import ArgumentParser
from collections import namedtuple
from datetime import datetime
import email
import email.policy
import os.path
import re
import shlex
import mailrules.sieve as sieve

######################################################################

class ShellCommandException(Exception):
    pass

######################################################################

class SilentArgumentParser(ArgumentParser):
    """
    An ArgumentParser that raises an exception instead of exiting on error.
    """
    def exit(self, status=0, message=None):
        if status:
            raise ShellCommandException(message)

######################################################################

def IsAway(procmail_context, args):
    try:
        # Find start_away_msg=... and end_away_msg=... statements in script
        with open(procmail_context.resolve_path('bin/is_away')) as f:
            assignments = [
                re.match(r'^\s*(?P<var>[a-z][a-z0-9_]*)=(?P<val>[^#\s]*)', line)
                for line in f
            ]
        assignments = {m.group('var'): m.group('val') for m in assignments if m}
        start = datetime.fromtimestamp(int(assignments['start_away_msg']))
        end = datetime.fromtimestamp(int(assignments['end_away_msg']))
    except (KeyError, OSError, ValueError):
        raise ShellCommandException("bin/is_away: Could not detect start and end times") from None
    yield sieve.AllofTest(
        sieve.CurrentDateTest('iso8601', start.isoformat(), match_type=':value "ge"'),
        sieve.CurrentDateTest('iso8601', end.isoformat(), match_type=':value "lt"'),
    )

######################################################################

def Vacation(procmail_context, args):
    """
    Support for emulating the vacation(1) command.
    """
    class VacationMessage(namedtuple('VacationMessage', 'reason subject from_addr mime')):
        def __new__(cls, reason, subject=None, from_addr=None, mime=False):
            return super().__new__(cls, reason, subject, from_addr, mime)

    class VacationMessageReader:
        def __init__(self, msg_path):
            self.msg_path = msg_path

        def __call__(self):
            try:
                with open(procmail_context.resolve_path(self.msg_path), encoding='UTF-8') as f:
                    msg = email.message_from_file(f, policy=email.policy.SMTPUTF8)
            except UnicodeDecodeError:
                with open(procmail_context.resolve_path(self.msg_path), encoding='ISO-8859-1') as f:
                    msg = email.message_from_file(f, policy=email.policy.SMTPUTF8)
            except OSError:
                raise ShellCommandException('No vacation message {}'.format(self.msg_path))
            subject = msg['Subject']
            del(msg['Subject'])
            from_addr = msg['From']
            del(msg['From'])
            mime = len(msg) > 0
            reason = re.sub(r'^(\r\n)+', '', str(msg if mime else msg.get_body()))
            return VacationMessage(reason, subject, from_addr, mime)

    p = SilentArgumentParser(prog='vacation')
    p.add_argument('login')
    p.add_argument('-a', metavar='alias', dest='alias', action='append',
        help="Handle messages for alias in the same manner as those received for the user's login name.")
    p.add_argument('-c', metavar='ccaddr', dest='ccaddr',
        help="Copy the vacation messages to ccaddr (ignored by Sieve)")
    p.add_argument('-d', dest='debug', action='store_true',
        help="Print messages to stderr instead of syslog (ignored by Sieve)")
    p.add_argument('-f', metavar='db',
        help="Uses db as the database file (ignored by Sieve)")
    p.add_argument('-m', metavar='msg', dest='read_vacation_msg',
        type=VacationMessageReader, default=VacationMessageReader('.vacation.msg'),
        help="Uses msg as the mssage file")
    p.add_argument('-j', action='store_true',
        help='Reply to the message even if our address cannot be found in the “To:” or “Cc:” headers (ignored by Sieve)')
    p.add_argument('-z', dest='fromaddr', action='store_const', const='<>',
        help='Set the envelope sender of the reply message to "<>"')

    invocation = p.parse_args(args)
    msg = invocation.read_vacation_msg()
    reason = msg.reason.replace('$SUBJECT', '${1}')
    subject = msg.subject.replace('$SUBJECT', '${1}') if msg.subject else None
    try:
        from_addr = invocation.fromaddr or msg.from_addr
        from_addr = procmail_context.resolve_email_address(from_addr)
    except KeyError as e:
        pass
    yield from procmail_context.context_chain(
        sieve.HeaderTest('subject', "*", match_type=':matches')
            if reason != msg.reason or subject != msg.subject else None,
        [
            sieve.VacationAction(
                reason=reason,
                subject=subject,
                from_addr=from_addr,
                addresses=invocation.alias,
                mime=msg.mime,
            )
        ]
    )


######################################################################

SUPPORTED_COMMANDS = {
    'bin/is_away': IsAway,
    '/usr/bin/vacation': Vacation,
}

def resolve_cmd(procmail_context, cmd):
    if '/' in cmd:
        return SUPPORTED_COMMANDS.get(cmd, None)
    for directory in procmail_context.getenv('PATH').split(':'):
        p = os.path.join(directory, cmd)
        if p in SUPPORTED_COMMANDS:
            return SUPPORTED_COMMANDS[p]
    return None

def parse_cmdline(procmail_context, cmdline):
    args = [procmail_context.interpolate(arg) for arg in shlex.split(cmdline)]
    cmd = resolve_cmd(procmail_context, args.pop(0)) if args else None
    if not cmd:
        raise ShellCommandException('Unsupported external command: ' + cmdline)
    yield from cmd(procmail_context, args)
