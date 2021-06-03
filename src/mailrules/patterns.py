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

import re

def ereg_as_wildcard(eregexp, anchor_start=True, anchor_end=True):
    r"""
    Attempt to convert an extended regular expression into a Sieve wildcard
    match.  (RFC 5228 Sec 2.7.1)

    >>> ereg_as_wildcard(r'')
    ''
    >>> ereg_as_wildcard(r'', False)
    '*'
    >>> print(ereg_as_wildcard(r'abc123'))
    abc123
    >>> print(ereg_as_wildcard(r'abc123', False))
    *abc123
    >>> print(ereg_as_wildcard(r'abc123', False, False))
    *abc123*
    >>> print(ereg_as_wildcard(r'.*abc123', False)) # Avoid redundant initial wildcard
    *abc123
    >>> print(ereg_as_wildcard(r'*abc123', False))  # Not even a valid eregexp
    None
    >>> print(ereg_as_wildcard(r'abc*'))
    None
    >>> print(ereg_as_wildcard(r'abc\*\?'))
    abc\*\?
    >>> print(ereg_as_wildcard(r'abc.'))
    abc?
    >>> print(ereg_as_wildcard(r'a@b\.c'))
    a@b.c
    >>> print(ereg_as_wildcard(r'abc{3}'))
    None
    >>> print(ereg_as_wildcard(r'ab[cd]'))
    None
    >>> print(ereg_as_wildcard(r'a|b'))
    None
    """
    result = [] if anchor_start else ['*']
    for match in re.finditer(
            r'(?P<quotable>\\[*?])|'
            r'\\(?P<unquotable>[.^$+?{}()\[\]|])|'
            r'(?P<anychars>\.\*)|'
            r'(?P<onechar>\.)|'
            r'(?P<literal>[^*.^$+?{}()\[\]|])|'
            r'(?P<irregular>.)',
            eregexp):
        if match.group('quotable'):
            result.append(match.group('quotable'))
        elif match.group('unquotable'):
            result.append(match.group('unquotable'))
        elif match.group('anychars'):
            if anchor_start or match.start() != 0:
                result.append('*')
        elif match.group('onechar'):
            result.append('?')
        elif match.group('literal'):
            result.append(match.group('literal'))
        else:
            return None
    pattern = ''.join(result)
    return pattern if anchor_end or pattern.endswith('*') else pattern + '*'
