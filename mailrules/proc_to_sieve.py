# Copyright 2020 Dara Poon and the University of British Columbia

from collections import namedtuple
from datetime import datetime, timezone
from itertools import chain, product, repeat, takewhile
import os
import re
import mailrules.procmailrc as procmailrc
import mailrules.sieve as sieve

try:
    import dateutil.tz
    tz = dateutil.tz.gettz(os.getenv('TZ'))
except ImportError:
    tz = timezone.utc

class RecipeMatch(namedtuple('RecipeMatch', 'flags conditions action')):
    def __new__(cls, flags=None, conditions=None, action=None):
        return super().__new__(cls, flags, conditions, action)

    def __call__(self, recipe):
        return isinstance(recipe, procmailrc.Recipe) and (
            all(
                getattr(self, attr) is None or
                    callable(getattr(self, attr)) and getattr(self, attr)(getattr(recipe, attr)) or
                    sorted(getattr(self, attr)) == sorted(''.join(getattr(recipe, attr).keys()))
                for attr in ('flags',)
            )
            and
            all(
                getattr(self, attr) is None or
                    callable(getattr(self, attr)) and getattr(self, attr)(getattr(recipe, attr)) or
                    getattr(self, attr) == getattr(recipe, attr)
                for attr in ('conditions', 'action')
            )
        )

IS_SPAMC_RUN = RecipeMatch(action=procmailrc.Pipe(command='spamc -f', var=None))
IS_ERRCHECK = RecipeMatch(flags='e', conditions=[], action=[
    procmailrc.Assignment(variable='EXITCODE', assign='=', value='$?')
])

# A kludge to recognize some specific subaddress-related recipes
HAS_COND_MAIL_EXTENSION = lambda recipe: RecipeMatch(conditions=[
        {'program_exitcode': 'test -n ${EXTENSION}'},
        {'program_exitcode': 'test -d ${MAILDIR}/.${EXTENSION}'},
    ])(recipe) or RecipeMatch(conditions=[
        {'program_exitcode': 'test -n "${EXTENSION}"'},
        {'program_exitcode': 'test -d "${MAILDIR}/.${EXTENSION}"'},
    ])(recipe) or RecipeMatch(conditions=[
        {'program_exitcode': 'test -n "${EXTENSION}" -a -d "${MAILDIR}/.${EXTENSION}"'},
    ])(recipe)


class FIXME(namedtuple('FIXME', 'problem placeholder'), sieve.Command):
    instances = 0

    def __new__(cls, problem, placeholder=None):
        cls.instances += 1
        return super().__new__(cls, problem, placeholder)

    def requires(self):
        if self.placeholder:
            yield from self.placeholder.requires()

    def __str__(self):
        s = str(self.placeholder) + ' ' if self.placeholder else ''
        return s + str(sieve.Comment('FIXME: {}'.format(self.problem)))

def Test(recipe_flags, recipe_conditions, context):
    def analyze_rhs(s):
        literal_re = re.fullmatch(r'(\^)?((?:[ A-Za-z0-9@_*?-]|\\.)*)(\$)?', s)
        if literal_re:
            rhs_string = re.sub(r'\\(.)', r'\g<1>', literal_re.group(2))
            if literal_re.group(1) and literal_re.group(3):
                return ':is', rhs_string
            else:
                return ':contains', rhs_string
        wildcard = re.fullmatch(r'(\^)?((?:\.\*|[ A-Za-z0-9@._-]|\\[*?\[\]])*)(\$)?', s)
        if wildcard:
            rhs_string = re.sub(
                r'(\.\*)|(\.)|(\\[*.])|\\([?\[\]])',
                lambda m: '*' if m.group(1) else '?' if m.group(2) else m.group(3) if m.group(3) else m.group(4),
                wildcard.group(2)
            )
            if not(wildcard.group(1) or rhs_string.startswith('*')):
                rhs_string = '*' + rhs_string
            if not(wildcard.group(3) or rhs_string.endswith('*')):
                rhs_string = rhs_string + '*'
            return ':matches', rhs_string
        else:
            return ':regexp', s

    def header_heuristic_fixup(r):
        # When people write From.*blah or ^Subject.*blah, they probably mean
        # ^From: .*blah or ^Subject: .*blah
        return re.sub(
            r'^\^?(?P<headers>(\()?(\|?(?:To|Reply-To|Cc|From|Sender|Subject))+(?(2)\)|)):?(?=\.\*)',
            r'^\g<headers>:',
            r,
            flags=re.I
        )

    def header_regexp_test(r):
        envelope_from = re.fullmatch(r'\^From (?P<value_re>.*)', r)
        if envelope_from:
            rel, rhs = analyze_rhs(envelope_from.group('value_re'))
            return sieve.EnvelopeTest('from', rhs, rel)
        literal_headers = re.fullmatch(r'\^(\()?(?P<headers>(\|?[A-Za-z0-9_-]+)*)(?(1)\)|): ?(?P<value_re>.*)', r)
        if literal_headers:
            headers = literal_headers.group('headers').split('|')
            rel, rhs = analyze_rhs(literal_headers.group('value_re'))
            return sieve.HeaderTest(headers if len(headers) > 1 else headers[0], rhs, rel)
        elif r == '^FROM_DAEMON':
            return sieve.AnyofTest(
                sieve.ExistsTest('Mailing-List'),
                sieve.HeaderTest('Precedence', '.*(junk|bulk|list)', match_type=':regexp'),
                sieve.HeaderTest('To', 'Multiple recipients of *', match_type=':matches'),
                sieve.AddressTest(
                    ['From', 'Sender', 'Resent-From', 'Resent-Sender', 'X-Envelope-From'],
                     '(?:'
                        'Post(ma?(st(e?r)?|n)|office)'
                        '|(send)?Mail(er)?'
                        '|daemon'
                        '|m(mdf|ajordomo)'
                        '|n?uucp'
                        '|LIST(SERV|proc)'
                        '|NETSERV'
                        '|o(wner|ps)'
                        '|r(e(quest|sponse)|oot)'
                        '|b(bounce|bs\.smtp)'
                        '|echo'
                        '|mirror'
                        '|s(erv(ices?|er)|mtp(error)?|ystem)'
                        '|A(dmin(istrator)?|MMGR|utoanswer)'
                     ').*'
                    ,
                    match_type=':regexp',
                    address_part=':localpart'
                )
            )
        elif r == '^FROM_MAILER':
            return sieve.AnyofTest(
                sieve.AddressTest(
                    ['From', 'Sender', 'Resent-From', 'Resent-Sender', 'X-Envelope-From'],
                     '(?:'
                        'Post(ma?(st(e?r)?|n)|office)'
                        '|(send)?Mail(er)?'
                        '|daemon'
                        '|mmdf'
                        '|n?uucp'
                        '|ops'
                        '|r(esponse|oot)'
                        '|(bbs\.)?smtp(error)?'
                        '|s(erv(ices?|er)|ystem)'
                        '|A(dmin(istrator)?|MMGR)'
                     ').*'
                    ,
                    match_type=':regexp',
                    address_part=':localpart'
                )
            )
        elif r.startswith('^TO'):
            rel, rhs = analyze_rhs(re.sub(r'\^TO[_ ]?', '', r))
            return sieve.HeaderTest(list(chain(
                (a + b for a, b in product(['', 'Original-', 'Resent-'], ['To', 'Cc', 'Bcc'])),
                ['X-Envelope-To', 'Apparently-To', 'Apparently-Resent-To']
            )), rhs, rel)
        return FIXME(r, placeholder=sieve.FalseTest())

    assert isinstance(recipe_conditions, list) and len(recipe_conditions)
    if len(recipe_conditions) > 1:
        return sieve.AllofTest(*[Test(recipe_flags, [t], context) for t in recipe_conditions])
    cond = recipe_conditions[0]
    test = (
        header_regexp_test(header_heuristic_fixup(cond.get('regexp')))
            if cond.get('regexp') and recipe_flags.get('H', True)
        else FIXME([recipe_flags, recipe_conditions], placeholder=sieve.FalseTest())
    )
    # Apply modifiers to the test
    if cond.get('weight'):
        test = FIXME([recipe_flags, recipe_conditions], placeholder=sieve.FalseTest())
    if cond.get('invert'):
        test = sieve.NotTest(test)
    return test


def Action(flags, action, context):
    def mailbox_name(s):
        return re.sub('^' + re.escape(context.initial.getenv('ORGMAIL')) + '(.*?)/?$', r'INBOX\g<1>', s)

    if isinstance(action, list) and len(action) == 1:
        if isinstance(action[0], procmailrc.Assignment):
            action = action[0]
        elif flags == action[0].flags:
            action = action[0].action

    if isinstance(action, procmailrc.Assignment):
        yield sieve.SetAction(action.variable, action.value)
    elif isinstance(action, procmailrc.Mailbox):
        if not flags.get('c', False):
            if action.destination == '/dev/null':
                yield sieve.DiscardAction()
                return
            elif context.interpolate(action.destination) == context.initial.getenv('ORGMAIL'):
                yield sieve.KeepAction()
                return
        copy = flags.get('c', False)
        yield sieve.FileintoAction(mailbox_name(context.interpolate(action.destination)), copy=copy, create=True)
    elif isinstance(action, procmailrc.Forward):
        for dest in action.destinations[:-1]:
            yield sieve.RedirectAction(context.interpolate(dest), copy=True)
        yield sieve.RedirectAction(context.interpolate(action.destinations[-1]), copy=flags.get('c', False))
    elif isinstance(action, procmailrc.Pipe):
        if re.match(r'^vacation\b', action.command):
            vacation_args = {'FIXME': context.interpolate(action.command)}
            yield sieve.VacationAction('FIXME: reason {0!r}'.format(vacation_args))
            if not flags.get('c', False):
                yield sieve.DiscardAction()
        else:
            yield FIXME(action)
    elif isinstance(action, list):
        yield from ProcmailrcGeneral(action, ProcmailContext(parent=context))
    else:
        yield FIXME(action)


class ProcmailContext:
    def __init__(self, env={}, parent=None, chain_type=None):
        self.env = dict(env)
        self.parent = parent
        self._initial = self if parent is None else parent.initial
        self.chain_type = chain_type

    def setenv(self, variable, value):
        self.env[variable] = self.interpolate(value)

    def getenv(self, variable, default=''):
        if variable in self.env:
            return self.env[variable]
        elif self.parent:
            return self.parent.getenv(variable, default)
        else:
            return default

    def interpolate(self, s):
        def subst_handler(match):
            if match.group('squoted'):
                return match.group('squoted')
            elif match.group('var'):
                return self.getenv(match.group('var'))
        return re.sub(
            r"'(?P<squoted>[^']*')"
            r'|\$(?P<brace>\{)?(?P<var>(?(brace)[A-Za-z0-9_]|[A-Za-z_])[A-Za-z0-9_]*)(?(brace)\})',
            subst_handler,
            s
        )

    @property
    def nest_level(self):
        return 0 if not self.parent else 1 + self.parent.nest_level

    @property
    def initial(self):
        return self._initial

    def context_chain(self, test, actions):
        #print("context chain self={} test={} actions={}".format(self, test, actions))
        if test is None and self.chain_type is None:
            if self.nest_level or self.chain_type == 'else':
                yield from actions
            else:
                yield sieve.IfControl(sieve.TrueTest(), actions)
        elif self.chain_type is None:
            yield sieve.IfControl(test, actions)
        elif test is None:
            # This should be a single delivering action
            assert len(actions) == 1
            yield from actions
        else:
            yield sieve.ElsifControl(test, actions)

    def __repr__(self):
        return 'ProcmailContext(env={0!r}, chain_type={1!r}, parent={2})'.format(self.env, self.chain_type, self.parent)

def Recipe(recipe, context):
    if HAS_COND_MAIL_EXTENSION(recipe):
        # FIXME: the recipe could have additional conditions (though in practice, unlikely)
        yield from context.context_chain(
            sieve.AllofTest(
                sieve.EnvelopeTest('to', "*", match_type=':matches', address_part=':detail'),
                sieve.MailboxExistsTest('INBOX.${1}'),
            ),
            list(Action(recipe.flags, recipe.action, ProcmailContext(env={'EXTENSION': '${1}'}, parent=context)))
        )
    else:
        test = Test(recipe.flags, recipe.conditions, context) if recipe.conditions else None
        yield from context.context_chain(
            test,
            list(Action(recipe.flags, recipe.action, context))
        )

######################################################################

def ProcmailrcGeneral(procmail_rules, context):
    for rule in procmail_rules:
        if isinstance(rule, procmailrc.Assignment):
            if isinstance(rule, procmailrc.Assignment):
                if rule.variable == 'INCLUDERC':
                    # This is a very special kind of "assignment"!
                    # TODO: transpile the included script too
                    yield FIXME('Need to transpile and install ' + rule.value)
                    yield sieve.IncludeControl(context.interpolate(rule.value))
                else:
                    context.setenv(rule.variable, rule.value)
                    if rule.variable not in ('PATH', 'LOCKFILE', 'LOGFILE', 'VERBOSE', 'LOGABSTRACT', 'SHELL', 'MAILDIR', 'DEFAULT', 'ORGMAIL'):
                        # This variable is not just for Procmail.  Maybe Sieve needs to know?
                        # TODO
                        yield sieve.SetAction(rule.variable, rule.value)
        elif isinstance(rule, procmailrc.Recipe):
            if context.chain_type == 'else' and not rule.conditions:
                # Slurp the rest in an else
                yield sieve.ElseControl(list(ProcmailrcGeneral(procmail_rules, ProcmailContext(parent=context))))
                return
            else:
                yield from Recipe(rule, context)
                if context.chain_type == 'else':
                    context = context.parent
        else:
            raise ValueError(rule)

def Procmailrc(procmailrc_path, context, provenance_comments=False):
    def rule_chunks(procmail_rule_iter):
        chunk_type, chunk = 'preamble', []
        for rule in procmail_rule_iter:
            if chunk_type == 'preamble' and not isinstance(rule, procmailrc.Assignment):
                if chunk:
                    yield chunk_type, chunk
                chunk_type, chunk = None, []

            chunk.append(rule)
            if rule.is_delivering:
                yield chunk_type, chunk
                chunk_type, chunk = 'else', []
        if chunk:
            yield chunk_type, chunk

    with open(procmailrc_path) as f:
        parser = procmailrc.Parser(procmailrc_path)
        procmail_rules = list(parser.parse_rules(parser.numbered_line_iter(f)))
        if provenance_comments:
            mtime = os.fstat(f.fileno()).st_mtime
            yield sieve.Comment('Converted from {} ({})'.format(
                procmailrc_path,
                datetime.fromtimestamp(mtime, tz).strftime('%Y-%m-%d %H:%M:%S %z')
            ))

    procmail_rule_iter = filter(lambda r: not(IS_SPAMC_RUN(r) or IS_ERRCHECK(r)), procmail_rules)

    for chunk_type, chunk in rule_chunks(procmail_rule_iter):
        #print(chunk_type, chunk)
        if chunk_type == 'preamble':
            yield from ProcmailrcGeneral(chunk, context)
        else:
            commands = list(ProcmailrcGeneral(chunk, ProcmailContext(parent=context, chain_type=chunk_type)))
            if not commands:
                yield FIXME('OUT OF COMMANDS?')
            else:
                yield from commands


# TODO:
# pattern recognition
# is_away
# notifications
# includes
