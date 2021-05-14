# Copyright 2020-2021 Dara Poon and the University of British Columbia

from collections import namedtuple
import re

######################################################################

Forward = namedtuple('Forward', 'destinations')
Mailbox = namedtuple('Mailbox', 'destination')
Pipe = namedtuple('Pipe', 'command var')

######################################################################

class Recipe(namedtuple('Recipe', 'flags conditions action')):
    def __new__(cls, action, flags={}, conditions=[]):
        return super().__new__(cls, flags, conditions, action)

    @property
    def is_delivering(self):
        """
        There are two kinds of recipes: delivering and non-delivering recipes.
        If a delivering recipe is found to match, procmail considers the mail
        (you guessed it) delivered and will cease processing the rcfile after
        having successfully executed the action line of the recipe. If a
        non-delivering recipe is found to match, processing of the rcfile will
        continue after the action line of this recipe has been executed.

        Delivering recipes are those that cause header and/or body of the mail
        to be: written into a file, absorbed by a program or forwarded to a
        mailaddress.

        Non-delivering recipes are: those that cause the output of a program or
        filter to be captured back by procmail or those that start a nesting
        block.

        You can tell procmail to treat a delivering recipe as if it were a
        non-delivering recipe by specifying the `c' flag on such a recipe. This
        will make procmail generate a carbon copy of the mail by delivering it
        to this recipe, yet continue processing the rcfile.
        """
        return not self.flags.get('c') and (
            any(
                isinstance(self.action, a) for a in [Forward, Mailbox, Pipe]
            )
            or
            isinstance(self.action, list) and
                any(a.is_delivering for a in self.action)       # FIXME
        )

    @classmethod
    def parse(cls, parser, numbered_line_iter):
        line_num, flag_line = next(numbered_line_iter)
        flags = cls._parse_flags(parser, line_num, flag_line)
        conditions = []
        for line_num, line in numbered_line_iter:
            if line.startswith('*'):
                conditions.append(cls._parse_condition(parser, line_num, line))
            else:
                numbered_line_iter.send((line_num, line))
                action = cls._parse_action(parser, numbered_line_iter)
                break
        return cls(action, flags, conditions)

    @staticmethod
    def _parse_flags(parser, line_num, line):
        assert line.lstrip().startswith(':0')
        flags = {}
        for match in re.finditer(
                r'(?:'
                    r'^\s*:0'
                    r'|(?P<H>H)'                # egrep header
                    r'|(?P<B>B)'                # egrep body
                    r'|(?P<D>D)'                # case sensitive
                    r'|(?P<A>A)'                # chain
                    r'|(?P<a>a)'                # chain if success
                    r'|(?P<E>E)'                # else
                    r'|(?P<e>e)'                # chain if failed
                    r'|(?P<h>h)'                # header pipe
                    r'|(?P<b>b)'                # body pipe
                    r'|(?P<f>f)'                # filter
                    r'|(?P<c>c)'                # cc
                    r'|(?P<w>w)'                # wait for status
                    r'|(?P<W>W)'                # wait for status quietly
                    r'|(?P<i>i)'                # ignore write errors
                    r'|(?P<r>r)'                # raw
                    r'|(?:\s*(?P<lock>:)\s*(?P<lockfile>\S+)?\s*(?:#.*)?$)'
                r')'
                r'\s*|(?P<unparseable>.+)', line):
            for flag, value in match.groupdict().items():
                if value is None or flag == 'lockfile':
                    continue
                if flag == 'unparseable':
                    raise ValueError('Invalid recipe flag at line {0}: {1}'.format(line_num, value))
                elif flag == 'lock':
                    flags[':'] = match.group('lockfile')
                else:
                    flags[flag] = True
        return flags

    @staticmethod
    def _parse_condition(parser, line_num, condition_line):
        assert condition_line.startswith('*')
        cond_def = {}
        for match in re.finditer(
                r'(?:'
                    r'^\*'
                    r'|\s+'
                    r'|(?P<weight>[+-]?(?:\d*\.)?\d+)^(?P<exponent>[+-]?(?:\d*\.)?\d+)\s*'
                    r'|(?P<invert>!)'
                    r'|(?P<shell>\$)'
                    r'|(?P<variablename>[A-Za-z_][A-Za-z_0-9]*)\s*\?\?'
                    r'|\?\s*(?P<program_exitcode>.*)'
                    r'|\<\s*(?P<shorter_than>\d+)\s*$'
                    r'|\>\s*(?P<longer_than>\d+)\s*$'
                    r'|(?P<regexp>.+)'
                r')', condition_line):
            for cond_type, value in match.groupdict().items():
                if value is not None:
                    cond_def[cond_type] = value
        return cond_def

    @staticmethod
    def _parse_action(parser, numbered_line_iter):
        line_num, line = next(numbered_line_iter)
        match = re.fullmatch(
            r'(?:'
                r'!\s*(?P<forward>[^#]+?)\s*'
                r'|(?:(?P<var>\S+)\s*=\s*)?\|\s*(?P<pipe>.*)'
                r'|(?P<nest_block>\{)'
                r'|(?P<mailbox>[^# ]+)'
            r')\s*(?:#.*)?',
            line
        )
        if not match:
            raise ValueError('Invalid action at {0} line {1}: "{2}"'.format(parser.filename, line_num, line))
        action = {}
        for group, value in match.groupdict().items():
            if value is not None:
                if group == 'nest_block':
                    parser.nest_level += 1
                    return list(parser.parse_rules(numbered_line_iter))
                elif group == 'forward':
                    return Forward(destinations=re.split(r'[,\s]+', value))
                elif group == 'mailbox':
                    return Mailbox(destination=value)
                elif group == 'pipe':
                    return Pipe(command=value, var=match.group('var'))

######################################################################

class Assignment(namedtuple('Assignment', 'variable assign value')):
    @classmethod
    def parse(cls, parser, line_num, line):
        match = re.fullmatch(r'(?P<var>[A-Za-z_][A-Za-z_0-9]*)\s*(?:(?P<assign>=)?\s*(?P<val>.*?))?\s*(?:#.*)?', line)
        if match is None:
            raise ValueError('Invalid assignment at file {0} line {1}: "{2}"'.format(parser.filename, line_num, line))
        return cls(match.group('var'), match.group('assign'), match.group('val'))

    @property
    def is_delivering(self):
        return False

######################################################################

class Parser:
    def __init__(self, filename):
        self.filename = filename
        self.nest_level = 0

    @staticmethod
    def numbered_folded_line_iter(lines):
        numbered_line_iter = (
            (line_num, line.strip())
            for line_num, line in enumerate(lines, 1)
            if not re.match(r'^\s*(?:#|$)', line)
        )
        for line_num, line in numbered_line_iter:
            while line.endswith('\\'):
                _, next_line = next(numbered_line_iter)
                line = re.sub(r'\\$', '', line) + next_line
            pushback = yield line_num, line
            if pushback is not None:
                yield
                yield pushback

    def parse_rules(self, numbered_line_iter):
        for line_num, line in numbered_line_iter:
            if line.lstrip() == '}':
                if self.nest_level <= 0:
                    raise ValueError('Unmatched "}}" at file {0} line {1}'.format(self.filename, line_num))
                self.nest_level -= 1
                break
            elif line.lstrip().startswith(':0'):
                numbered_line_iter.send((line_num, line))
                yield Recipe.parse(self, numbered_line_iter)
            else:
                yield Assignment.parse(self, line_num, line)
        else:
            # Exited loop because no more lines.  Assert that nest_level == 0.
            if self.nest_level:
                raise ValueError('Unmatched braces at EOF in {0}'.format(self.filename))
