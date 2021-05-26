# Copyright 2021 Dara Poon and the University of British Columbia
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

from argparse import ArgumentParser
from collections import namedtuple
from datetime import datetime
import email
import email.policy
from email.utils import formataddr, parseaddr
from itertools import product
import os.path
import re
import shlex
import mailrules.proc_to_sieve
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

def Procmail(procmail_context, args):
    p = SilentArgumentParser(prog='procmail')
    p.add_argument('-v', dest='version', action='store_true',
        help="Do nothing, successfully")
    p.add_argument('-d', metavar='recipient', dest='recipient',
        help="Explicit delivery mode (unsupported by Sieve)")
    p.add_argument('-m', dest='general_mail_filter', action='store_true',
        help="General-purpose mail filter (unsupported by Sieve)")
    p.add_argument('rcfile', nargs='?', default='.procmailrc',
        help="procmailrc file (Sieve only supports one rcfile)")

    invocation, extra_args = p.parse_known_args(args)
    if invocation.version:
        return
    elif invocation.recipient:
        raise ShellCommandException("procmail -d: Unsupported mode")
    elif invocation.general_mail_filter:
        raise ShellCommandException("procmail -m: Unsupported mode")
    else:
        try:
            yield from mailrules.proc_to_sieve.Procmailrc(
                procmail_context.resolve_path(invocation.rcfile),
                mailrules.proc_to_sieve.ProcmailContext(parent=procmail_context, chain_type=None)
            )
        except OSError as e:
            raise ShellCommandException(str(e))

######################################################################

def SpamAssassin(procmail_context, args):
    """
    Emulation for reading ~/.spamassassin/user_prefs to convert directives into
    Sieve rules that override SpamAssassin results.

    We presume that the message has already been passed through SpamAssassin by
    the time the Sieve filter is executed, and that such execution of
    SpamAssassin is in a global rather than a per-user context, such that it
    does not respect the user's personal configuration in
    ~/.spamassassin/user_prefs.                                                           
                                                                                                                           
    Therefore, if procmail contains an invocation of spamc, the Sieve script
    will instead manipulate the message's SpamAssassin-produced headers to make
    it look like spam (effectively blacklisting it) or look like ham
    (effectively whitelisting it).                      

    https://spamassassin.apache.org/doc/Mail_SpamAssassin_Conf.html
    """
    ACTIONS = {
        'blacklist': [
            sieve.DeleteHeaderAction('X-Spam-Flag'),
            sieve.AddHeaderAction('X-Spam-Flag', 'YES'),
            sieve.DeleteHeaderAction('X-Spam-Level'),
            sieve.AddHeaderAction('X-Spam-Level', '*' * 99),
            sieve.DeleteHeaderAction('X-Spam-Status'),
            sieve.AddHeaderAction('X-Spam-Status', 'Yes, score=100.0 required=5.0'),
        ],
        'whitelist': [
            sieve.DeleteHeaderAction('X-Spam-Flag'),
            sieve.DeleteHeaderAction('X-Spam-Level'),
            sieve.DeleteHeaderAction('X-Spam-Status'),
        ],
    }
    HEADER_TESTS = {
        'from': [
            #'Envelope-Sender', Forbidden AddressTest
            'Resent-Sender',
            #'X-Envelope-From', Forbidden AddressTest
            'From',
        ],
        'to': [
            'To',
            'Cc',
            'Apparently-To',
            'Delivered-To',
            #'Envelope-Recipients', Forbidden AddressTest
            #'Apparently-Resent-To', Forbidden AddressTest
            #'X-Envelope-To', Forbidden AddressTest
            #'Envelope-To', Forbidden AddressTest
            #'X-Delivered-To', Forbidden AddressTest
            'X-Original-To',
            #'X-Rcpt-To', Forbidden AddressTest
            #'X-Real-To', Forbidden AddressTest
        ],
    }
    WB_LIST_KEYWORDS = ['{}_{}'.format(action, test) for action, test in product(ACTIONS, HEADER_TESTS)]

    def user_pref_directives():
        try:
            with open(procmail_context.resolve_path('.spamassassin/user_prefs')) as f:
                for line in f:
                    match = re.match(r'\s*(?P<keyword>[^#\s]+)\s+(?P<value>[^#]*)', line.rstrip())
                    if match:
                        yield match.group('keyword'), match.group('value')
        except OSError:
            pass

    def collated_user_prefs(directives):
        prefs = {}
        for keyword, value in directives:
            if keyword in WB_LIST_KEYWORDS:
                prefs.setdefault(keyword, []).extend(re.split(r'[,\s]+', value))
        return prefs

    wb_lists = collated_user_prefs(user_pref_directives())
    for keyword in WB_LIST_KEYWORDS:
        if wb_lists.get(keyword):
            action, header_test = keyword.split('_', 1)
            yield sieve.IfControl(
                sieve.AddressTest(
                    HEADER_TESTS[header_test],
                    wb_lists[keyword],
                    match_type=':matches'
                ),
                ACTIONS[action],
                rule_name="SpamAssassin override {}".format(keyword)
            )

######################################################################

def Vacation(procmail_context, args):
    """
    Support for emulating the vacation(1) command.
    """
    class VacationMessage(namedtuple('VacationMessage', 'reason subject from_addr mime')):
        def __new__(cls, reason, subject=None, from_addr=None, mime=False):
            return super().__new__(cls, reason, subject, from_addr, mime)

    MISSING_VACATION_MESSAGE = VacationMessage(
        'Content-Type: text/plain; format=flowed\r\n\r\n'
        'I will not be reading my mail for a while. '
        'Your mail concerning \r\n"$SUBJECT" \r\n'
        'will be read when I return.',
        subject='Re: $SUBJECT',
        mime=True,
    )

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
                return MISSING_VACATION_MESSAGE
            subject = msg['Subject']
            del(msg['Subject'])
            from_addr = msg['From']
            del(msg['From'])
            mime = len(msg) > 0
            reason = re.sub(r'^(\r\n)+', '', str(msg if mime else msg.get_body()))
            return VacationMessage(reason, subject, from_addr, mime)

    p = SilentArgumentParser(prog='vacation')
    p.add_argument('login')
    p.add_argument('-a', metavar='alias', dest='aliases', action='append',
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
    p.add_argument('-z', dest='nullsender', type=bool,
        help='Set the envelope sender of the reply message to "<>"')

    invocation = p.parse_args(args)
    msg = invocation.read_vacation_msg()
    reason = msg.reason.replace('$SUBJECT', '${1}')
    subject = msg.subject.replace('$SUBJECT', '${1}') if msg.subject else None
    test = None
    if reason != msg.reason or subject != msg.subject:
        test = sieve.HeaderTest('subject', "*", match_type=':matches')

    if invocation.nullsender:
        from_addr = None
    else:
        realname, email_address = parseaddr(msg.from_addr)
        if ' ' in email_address and not realname:
            # Heuristic fixup
            realname, email_address = msg.from_addr.addresses[0].username, None
        if not email_address:
            email_address = invocation.aliases[0] if invocation.aliases else invocation.login
        if not realname and (email_address == procmail_context.initial.getenv('LOGNAME')):
            email_address = None
        from_addr = formataddr((realname, procmail_context.resolve_email_address(email_address)))

    yield from procmail_context.context_chain(
        sieve.FalseTest(placeholder=test) if msg == MISSING_VACATION_MESSAGE else test,
        [
            sieve.VacationAction(
                reason=reason,
                subject=subject,
                from_addr=from_addr,
                addresses=[
                    procmail_context.resolve_email_address(a)
                    for a in invocation.aliases
                    or []
                ],
                mime=msg.mime,
            )
        ]
    )


######################################################################

SUPPORTED_COMMANDS = {
    'bin/is_away': IsAway,
    '/usr/bin/procmail': Procmail,
    '/usr/bin/spamc': SpamAssassin,
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
