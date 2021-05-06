# Copyright 2020-2021 Dara Poon and the University of British Columbia

from collections import namedtuple
import re

######################################################################

def quote(s):
    """RFC 5228 Sec 2.4.2"""
    if '\n' not in s:
        return '"{0}"'.format(re.sub(r'[\"]', r'\\\g<0>', s))
    return 'text:\r\n' + re.sub(r'^\.', '..', s, flags=re.MULTILINE) + '\r\n.\r\n'

def string_list(obj):
    """RFC 5228 Sec 2.4.2.1"""
    return (
        '[' + ', '.join(quote(o) for o in obj) + ']'
            if isinstance(obj, (list, set)) and len(obj) > 1 else
        quote(obj[0]) if isinstance(obj, (list, set)) else
        quote(obj)
    )

def make_list(obj):
    return list(obj) if isinstance(obj, (list, set)) else [obj]

######################################################################

class Command:
    def requires(self):
        # Generator that yields nothing (https://stackoverflow.com/a/13243870)
        return
        yield

    @property
    def name(self):
        return ''

class Comment(namedtuple('Comment', 'text'), Command):
    """RFC 5228 Sec 2.3"""
    def __str__(self):
        if '\n' in self.text:
            return '/* ' + self.text.replace('*/', '* /') + ' */'
        else:
            return '# ' + self.text

class IfControl(namedtuple('IfControl', 'test command'), Command):
    """RFC 5228 Sec 3.1"""
    def requires(self):
        yield from self.test.requires()
        for c in make_list(self.command):
            yield from c.requires()

    @property
    def name(self):
        return next(filter(None, (cmd.name for cmd in make_list(self.command))), self.test.name)

    def __str__(self):
        return 'if {0}\r\n{{\r\n    {1}\r\n}}'.format(
            self.test,
            '\r\n    '.join(str(c) for c in make_list(self.command))
        )

class ElsifControl(namedtuple('ElsifControl', 'test command'), Command):
    """RFC 5228 Sec 3.1"""
    def requires(self):
        yield from self.test.requires()
        for c in make_list(self.command):
            yield from c.requires()

    @property
    def name(self):
        return next(filter(None, (cmd.name for cmd in make_list(self.command))), self.test.name)

    def __str__(self):
        return 'elsif {0}\r\n{{\r\n    {1}\r\n}}'.format(
            self.test,
            '\r\n    '.join(str(c) for c in make_list(self.command))
        )

class ElseControl(namedtuple('ElseControl', 'command'), Command):
    """RFC 5228 Sec 3.1"""
    def requires(self):
        for c in make_list(self.command):
            yield from c.requires()

    @property
    def name(self):
        return next(filter(None, (cmd.name for cmd in make_list(self.command))), '')

    def __str__(self):
        return 'else\r\n{{\r\n    {0}\r\n}}'.format(
            '\r\n    '.join(str(c) for c in make_list(self.command))
        )

class RequireControl(namedtuple('RequireControl', 'extension'), Command):
    """RFC 5228 Sec 3.2"""
    def __str__(self):
        return 'require ' + string_list(self.extension) + ';'

class StopControl(Command):
    """RFC 5228 Sec 3.3"""
    def __str__(self):
        return 'stop;'

class FileintoAction(namedtuple('Fileinto', 'mailbox copy create'), Command):
    """RFC 5228 Sec 4.1, RFC 3894 Sec 3, and RFC 5490 Sec 3.2"""
    def __new__(cls, mailbox, copy=False, create=False):
        return super().__new__(cls, mailbox, copy, create)

    def requires(self):
        yield 'fileinto'
        if self.copy: yield 'copy'
        if self.create: yield 'mailbox'

    @property
    def name(self):
        mbox_name = re.sub(r'^INBOX\.', '', self.mailbox)
        return None if mbox_name.startswith('$') else mbox_name

    def __str__(self):
        s = 'fileinto'
        if self.copy:
            s += ' :copy'
        if self.create:
            s += ' :create'
        return s + ' ' + quote(self.mailbox) + ';'

class RedirectAction(namedtuple('Redirect', 'address copy'), Command):
    """RFC 5228 Sec 4.2 and RFC 3894 Sec 3"""
    def __new__(cls, address, copy=False):
        return super().__new__(cls, address, copy)

    def requires(self):
        if self.copy: yield 'copy'

    @property
    def name(self):
        return self.address

    def __str__(self):
        return 'redirect{1} {0};'.format(quote(self.address), ' :copy' if self.copy else '')

class KeepAction(Command):
    """RFC 5228 Sec 4.2"""
    @property
    def name(self):
        return 'Keep'

    def __str__(self):
        return 'keep;'

class DiscardAction(Command):
    """RFC 5228 Sec 4.2"""
    @property
    def name(self):
        return 'Discard'

    def __str__(self):
        return 'discard;'

class AddressTest(namedtuple('AddressTest', 'header key match_type address_part comparator'), Command):
    """RFC 5228 Sec 5.1"""
    def __new__(cls, header, key, match_type=':is', address_part=':all', comparator='i;ascii-casemap'):
        return super().__new__(cls, header, key, match_type, address_part, comparator)

    def requires(self):
        # TODO
        if self.address_part == ':detail':
            # RFC 5233: Subaddress extension
            yield 'subaddress'

    @property
    def name(self):
        return self.key

    def __str__(self):
        s = 'address'
        if self.comparator != 'i;ascii-casemap':
            s += ' :comparator ' + quote(self.comparator)
        if self.match_type != ':is':
            s += ' ' + self.match_type
        if self.address_part != ':all':
            s += ' ' + self.address_part
        s += ' ' + string_list(self.header)
        s += ' ' + string_list(self.key)
        return s

class AllofTest(namedtuple('AllofTest', 'tests'), Command):
    """RFC 5228 Sec 5.2"""
    def __new__(cls, *tests):
        return super().__new__(cls, tests)

    def requires(self):
        for c in self.tests:
            yield from c.requires()

    @property
    def name(self):
        return next(filter(None, (test.name for test in self.tests)), '')

    def __str__(self):
        return 'allof(' + ', '.join(str(t) for t in self.tests) + ')'

class AnyofTest(namedtuple('AnyofTest', 'tests'), Command):
    """RFC 5228 Sec 5.3"""
    def __new__(cls, *tests):
        return super().__new__(cls, tests)

    def requires(self):
        for c in self.tests:
            yield from c.requires()

    @property
    def name(self):
        return next(filter(None, (test.name for test in self.tests)))

    def __str__(self):
        return 'anyof(' + ', '.join(str(t) for t in self.tests) + ')'

class EnvelopeTest(namedtuple('EnvelopeTest', 'envelope_part key match_type address_part comparator'), Command):
    """RFC 5228 Sec 5.4"""
    def __new__(cls, envelope_part, key, match_type=':is', address_part=':all', comparator='i;ascii-casemap'):
        return super().__new__(cls, envelope_part, key, match_type, address_part, comparator)

    def requires(self):
        yield 'envelope'
        # TODO: Plugin system?
        if self.address_part == ':detail':
            # RFC 5233: Subaddress extension
            yield 'subaddress'
        if self.match_type == ':matches':
            yield 'variables'

    @property
    def name(self):
        if self.match_type == ':matches' and self.key == '*':
            return "Envelope {0}".format(self.envelope_part.replace(':', ''))
        else:
            return self.key

    def __str__(self):
        s = 'envelope'
        if self.address_part != ':all':
            s += ' ' + self.address_part
        if self.comparator != 'i;ascii-casemap':
            s += ' :comparator ' + quote(self.comparator)
        if self.match_type != ':is':
            s += ' ' + self.match_type
        s += ' ' + string_list(self.envelope_part)
        s += ' ' + string_list(self.key)
        return s


class ExistsTest(namedtuple('ExistsTest', 'header'), Command):
    """RFC 5228 Sec 5.5"""
    def __str__(self):
        return 'exists ' + string_list(self.header)

class FalseTest(namedtuple('FalseTest', 'placeholder'), Command):
    """RFC 5228 Sec 5.6"""
    def __new__(cls, placeholder=None):
        return super().__new__(cls, placeholder)

    def __str__(self):
        if self.placeholder:
            return 'false # {}'.format(self.placeholder)
        return 'false'

class HeaderTest(namedtuple('HeaderTest', 'header key match_type comparator'), Command):
    """RFC 5228 Sec 5.7"""
    def __new__(cls, header, key, match_type=':is', comparator='i;ascii-casemap'):
        return super().__new__(cls, header, key, match_type, comparator)

    def requires(self):
        if self.match_type == ':matches':
            yield 'variables'

    @property
    def name(self):
        return '{} {}'.format(self.header, self.key)

    def __str__(self):
        s = 'header'
        if self.comparator != 'i;ascii-casemap':
            s += ' :comparator ' + quote(self.comparator)
        if self.match_type != ':is':
            s += ' ' + self.match_type
        s += ' ' + string_list(self.header)
        s += ' ' + string_list(self.key)
        return s

class NotTest(namedtuple('NotTest', 'test'), Command):
    """RFC 5228 Sec 5.8"""
    def requires(self):
        yield from self.test.requires()

    @property
    def name(self):
        return 'not ' + self.test.name if self.test.name else ''

    def __str__(self):
        return 'not ' + str(self.test)

class TrueTest(Command):
    """RFC 5228 Sec 5.6"""
    def __str__(self):
        return 'true'


######################################################################

class SetAction(namedtuple('SetAction', 'name value modifier'), Command):
    """RFC 5229 Sec 4"""
    def __new__(cls, name, value, modifier=None):
        return super().__new__(cls, name, value, modifier)

    def requires(self):
        yield 'variables'

    def __str__(self):
        return 'set{2} {0} {1};'.format(
            quote(self.name),
            quote(self.value),
            ' ' + self.modifier if self.modifier else ''
        )

######################################################################

class MailboxExistsTest(namedtuple('MailboxExistsTest', 'mailbox'), Command):
    """RFC 5490 Sec 3.1"""
    def requires(self):
        yield 'mailbox'

    def __str__(self):
        return 'mailboxexists ' + string_list(self.mailbox)

######################################################################

class VacationAction(namedtuple('VacationAction', 'reason days seconds subject from_addr addresses mime handle'), Command):
    """RFC 5231 (vacation) or RFC 6131 (vacation-seconds)"""
    def __new__(cls, reason, days=None, seconds=None, subject=None, from_addr=None, addresses=None, mime=False, handle=None):
        return super().__new__(cls, reason, days, seconds, subject, from_addr, addresses, mime, handle)

    def requires(self):
        yield 'vacation-seconds' if self.seconds is not None else 'vacation'

    @property
    def name(self):
        return 'Vacation'

    def __str__(self):
        s = 'vacation'
        if self.seconds is not None:
            # :seconds 0 is allowed (RFC 6131 Sec 2)
            s += ' seconds {0!d}'.format(self.seconds)
        elif self.days:
            # :days 0 is not allowed (RFC 5230 Sec 4.1)
            s += ' days {0!d}'.format(self.days)
        if self.subject:
            s += ' :subject {0}'.format(quote(self.subject))
        if self.from_addr:
            s += ' :from {0}'.format(quote(self.from_addr))
        if self.addresses:
            s += ' :addresses {0}'.format(string_list(self.addresses))
        if self.mime:
            s += ' :mime'
        if self.handle:
            s += ' :handle {0}'.format(quote(self.handle))
        return s + ' ' + quote(self.reason) + ';'

######################################################################

class CurrentDateTest(namedtuple('CurrentDateText', 'date_part key zone originalzone comparator match_type'), Command):
    """RFC 5260 Sec 5"""
    def __new__(cls, date_part, key, zone=None, originalzone=None, comparator='i;ascii-casemap', match_type=':is'):
        if zone is not None and originalzone is not None:
            raise ValueError('currentdate must not have both :zone and :originalzone')
        return super().__new__(cls, date_part, key, zone, originalzone, comparator, match_type)

    def requires(self):
        yield 'date'
        if self.match_type.startswith(':value'):
            # RFC 5231 Sec 4.1
            yield 'relational'

    def __str__(self):
        s = 'currentdate'
        if self.comparator != 'i;ascii-casemap':
            s += ' :comparator ' + quote(self.comparator)
        if self.match_type != ':is':
            s += ' ' + self.match_type
        if self.zone:
            s += ' :zone {0}'.format(quote(self.zone))
        elif self.originalzone:
            s += ' :originalzone'
        s += ' {0} {1}'.format(quote(self.date_part), string_list(self.key))
        return s

######################################################################

class IncludeControl(namedtuple('IncludeControl', 'value location once optional'), Command):
    """RFC 6609 Sec 3.2"""
    def __new__(cls, value, location=':personal', once=False, optional=False):
        if location not in (':personal', ':global'):
            raise ValueError('include :location must be :personal or :global')
        return super().__new__(cls, value, location, once, optional)

    def requires(self):
        yield 'include'

    def __str__(self):
        s = 'include'
        if self.location == ':global':
            s += ' :global'
        if self.once:
            s += ' :once'
        if self.optional:
            s += ' :optional'
        return s + ' ' + quote(self.value) + ';'


class ReturnControl(Command):
    """RFC 6609 Sec 3.3"""
    def requires(self):
        yield 'include'

    def __str__(self):
        return 'return;'


class GlobalControl(namedtuple('GlobalControl', 'value'), Command):
    """RFC 6609 Sec 3.4"""
    def requires(self):
        yield 'include'

    def __str__(self):
        return 'global ' + string_list(self.value) + ';'


######################################################################

class Script(Command):
    def __init__(self):
        self.commands = []

    def requires(self):
        for c in self.commands:
            yield from c.requires()

    def add_command(self, command):
        name = command.name
        if name:
            self.commands.append(Comment('rule:[{}]'.format(name)))
        self.commands.append(command)

    def __str__(self):
        out = []
        requirements = sorted(set(self.requires()))
        if requirements:
            out.append(RequireControl(requirements))
        out.extend(self.commands)
        if out and isinstance(out[-1], StopControl):
            # A final stop is superfluous
            out.pop()
        if out and str(out[-1]) == 'keep;':
            # RFC 5228 Sec 2.10.2: final keep is superfluous
            out.pop()
        return '\r\n'.join('{0}'.format(command) for command in out)

