#!/usr/bin/env python3

# Twister v0.9
# https://github.com/mh0x/twister


import argparse
import collections
import concurrent.futures
import copy
import itertools
import json
import os
import re
import requests
import sys


__version__ = '0.9'
__author__ = 'https://github.com/mh0x'

script_name = 'Twister v' + __version__ + ' (' + __author__ + '/twister)'
script_desc = '''
Permutation engine for generating and checking the availability of malicious
Twitter usernames. Several edit operations are supported: substitution,
transposition, insertion, deletion, and prefix/suffix.
'''
script_usage = '''twister.py [-h] [-c] [-q] [-o OUTPUT] [-n THREADS]
                  [-r RETRIES] [-t TIMEOUT] profile user [user ...]'''
script_epilog = '''
edit operations:                              notation:
  {"sub": {x: [y, ...], ...}, "max": n}         x, y  characters
  {"tra": [[x, y], ...], "max": n}              u     strings
  {"ins": {x: [y, ...], ...}, "max": n}         n     positive integers
  {"del": [x, ...], "max": n}
  {"pre": [u, ...]}
  {"suf": [u, ...]}'''

default_threads = 5
default_retries = 2
default_timeout = 10

valid_chars = re.compile('^[a-zA-Z0-9_]+$')
endpoint_url = 'https://twitter.com/users/username_available?username='


def error(err):
    print('[!] error: ' + str(err), file=sys.stderr)


def info(msg, quiet=False):
    if not quiet:
        print('[*] ' + msg)


def success(msg, quiet=False):
    if not quiet:
        print('[+] ' + msg)


def failure(msg, quiet=False):
    if not quiet:
        print('[-] ' + msg)


def prologue(quiet=False):
    if not quiet:
        print(script_name)


def unique(elems):
    return list(collections.OrderedDict.fromkeys(elems))


class EditOp:
    def __init__(self, cases, max=1):
        self.cases = cases
        self.max = max

    def apply(self, string):
        strs = []
        edits = self.edits(string)
        for i in range(self.max):
            for edit in [[*e] for e in itertools.combinations(edits, i+1)]:
                strs.extend(self.generate(string, edit))
        return strs


class SubOp(EditOp):
    def generate(self, string, edit):
        strs = []
        for ed in itertools.product(*[e[1] for e in edit]):
            chars = list(string)
            for i, char in enumerate(ed):
                chars[edit[i][0]] = char
            strs.append(''.join(chars))
        return strs

    def edits(self, string):
        return [(i, self.cases[c]) for i, c in enumerate(string)
                if c in self.cases]


class TraOp(EditOp):
    def generate(self, string, edit):
        chars = list(string)
        for i in edit:
            char = chars[i]
            chars[i] = chars[i+1]
            chars[i+1] = char
        return [''.join(chars)]

    def edits(self, string):
        return [i for i in range(len(string)-1)
                if [string[i], string[i+1]] in self.cases]


class InsOp(EditOp):
    def generate(self, string, edit):
        strs = []
        for ed in itertools.product(*[e[1] for e in edit]):
            chars = list(string)
            for i, char in enumerate(ed):
                chars[edit[i][0]] += char
            chars = ''.join(chars)
            if len(chars) <= 15:
                strs.append(chars)
        return strs

    def edits(self, string):
        return [(i, self.cases[c]) for i, c in enumerate(string)
                if c in self.cases]


class DelOp(EditOp):
    def generate(self, string, edit):
        chars = [c for i, c in enumerate(string) if i not in edit]
        return [''.join(chars)] if chars else []

    def edits(self, string):
        return [i for i, c in enumerate(string) if c in self.cases]


class PreOp(EditOp):
    def apply(self, string):
        strings = []
        for string1 in self.cases:
            string2 = string1 + string
            if len(string2) <= 15:
                strings.append(string2)
        return strings


class SufOp(EditOp):
    def apply(self, string):
        strings = []
        for string1 in self.cases:
            string2 = string + string1
            if len(string2) <= 15:
                strings.append(string2)
        return strings


class ArgParser(argparse.ArgumentParser):
    def format_help(self):
        formatter = self._get_formatter()
        formatter.add_text(script_name)
        formatter.add_text(self.description)
        formatter.add_usage(self.usage, self._actions,
                            self._mutually_exclusive_groups)
        for action_group in self._action_groups:
            formatter.start_section(action_group.title)
            formatter.add_text(action_group.description)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()
        formatter.add_text(self.epilog)
        return formatter.format_help()

    def error(self, msg):
        raise argparse.ArgumentTypeError(msg.replace('\'', '') + os.linesep*2 +
                                         self.format_usage().rstrip())


def help_formatter(prog):
    return argparse.RawTextHelpFormatter(prog, max_help_position=40)


def arg_default(default):
    return '(default: ' + str(default) + ')'


def arg_error(obj, desc, msg=''):
    raise argparse.ArgumentTypeError(
        'invalid ' + desc + ': ' + str(obj).replace('\'', '"')
        + (' (' + msg + ')' if msg else ''))


def check_type(obj, typ, desc, msg=''):
    if not isinstance(obj, typ):
        arg_error(obj, desc, msg)


def check_list(obj, desc):
    check_type(obj, list, desc, 'expected an array')


def check_dict(obj, desc):
    check_type(obj, dict, desc, 'expected an object')


def parse_str(obj, desc, min=1, max=15):
    check_type(obj, str, desc, 'expected a string')
    if min == max and len(obj) != min:
        arg_error(obj, desc, 'expected ' + str(min) + ' chars'
                             + ('' if min == 1 else 's'))
    if len(obj) < min:
        arg_error(obj, desc, 'min length is ' + str(min))
    if len(obj) > max:
        arg_error(obj, desc, 'max length is ' + str(max))
    if not valid_chars.match(obj):
        arg_error(obj, desc, 'valid chars: a-z, A-Z, 0-9, _')
    return obj.lower()


def parse_str_set(obj, desc, min=1, max=15):
    check_list(obj, desc + ' set')
    return unique([parse_str(o, desc, min, max) for o in obj])


def parse_char(obj):
    return parse_str(obj, 'char', max=1)


def parse_char_set(obj):
    return parse_str_set(obj, 'char', max=1)


def parse_int(obj):
    try:
        num = int(obj)
    except ValueError:
        arg_error(obj, 'int value')
    return num


def parse_nneg_int(obj):
    num = parse_int(obj)
    if num < 0:
        arg_error(num, 'int value', 'must be non-negative')
    return num


def parse_pos_int(obj):
    num = parse_int(obj)
    if num < 1:
        arg_error(num, 'int value', 'must be positive')
    return num


def parse_op(obj, key, max=True):
    op = {}
    for k in obj:
        if k == key or (max and k == 'max'):
            op[k] = copy.copy(obj[k])
        else:
            arg_error(k, 'operation property')
    if max and 'max' not in op:
        arg_error(obj, 'operation', 'missing max property')
    return op


def parse_sub_op(obj):
    op = parse_op(obj, 'sub')
    check_dict(op['sub'], 'operation property')
    subs = {}
    for string, obj in op['sub'].items():
        char = parse_char(string)
        chars = [c for c in parse_char_set(obj) if c != char]
        if chars:
            subs[char] = chars
    return SubOp(subs, parse_pos_int(op['max']))


def parse_tra_op(obj):
    op = parse_op(obj, 'tra')
    check_list(op['tra'], 'operation property')
    tras = []
    for obj in op['tra']:
        chars = parse_char_set(obj)
        if len(chars) != 2:
            arg_error(chars, 'operation property', 'expected two charaters')
        if chars not in tras:
            tras.append(chars)
    return TraOp(tras, parse_pos_int(op['max']))


def parse_ins_op(obj):
    op = parse_op(obj, 'ins')
    check_dict(op['ins'], 'operation property')
    ins = {parse_char(s): parse_char_set(o) for s, o in op['ins'].items()}
    return InsOp(ins, parse_pos_int(op['max']))


def parse_del_op(obj):
    op = parse_op(obj, 'del')
    return DelOp(parse_char_set(obj['del']), parse_pos_int(op['max']))


def parse_pre_op(obj):
    return PreOp(parse_str_set(
                 parse_op(obj, 'pre', False)['pre'], 'prefix', max=14))


def parse_suf_op(obj):
    return SufOp(parse_str_set(
                 parse_op(obj, 'suf', False)['suf'], 'suffix', max=14))


op_parsers = {'sub': parse_sub_op, 'tra': parse_tra_op,
              'ins': parse_ins_op, 'del': parse_del_op,
              'pre': parse_pre_op, 'suf': parse_suf_op}


def parse_profile(string):
    try:
        if os.path.isfile(string):
            with open(string, 'r') as fp:
                obj = json.load(fp)
        else:
            obj = json.loads(string)
    except (IOError, json.JSONDecodeError) as err:
        raise argparse.ArgumentTypeError(str(err))
    check_list(obj, 'profile')
    profile = []
    for obj1 in obj:
        check_dict(obj1, 'operation')
        keys = [k for k in obj1 if k in op_parsers]
        if len(keys) == 1:
            profile.append(op_parsers[keys[0]](obj1))
        elif keys:
            arg_error(obj1, 'operation', 'ambiguous properties')
        else:
            arg_error(obj1, 'operation')
    return profile


def parse_user(string):
    if string and string[0] == '@':
        string = string[1:]
    return parse_str(string, 'username')


def parse_args():
    parser = ArgParser(description=script_desc, usage=script_usage,
                       epilog=script_epilog, formatter_class=help_formatter)
    parser.add_argument('profile', type=parse_profile,
                        help='generator profile json')
    parser.add_argument('user', type=parse_user, nargs='+',
                        help='target username(s)')
    parser.add_argument('-c', '--check', action='store_true',
                        help='check availability of generated usernames')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='suppress messages sent to stdout')
    parser.add_argument('-o', '--output', type=argparse.FileType('w'),
                        help='output results to csv file')
    parser.add_argument('-n', '--threads', type=parse_pos_int,
                        default=default_threads,
                        help=('max concurrent requests '
                              + arg_default(default_threads)))
    parser.add_argument('-r', '--retries', type=parse_nneg_int,
                        default=default_retries,
                        help=('max request retries '
                              + arg_default(default_retries)))
    parser.add_argument('-t', '--timeout', type=parse_pos_int,
                        default=default_timeout,
                        help=('request timeout, secs '
                              + arg_default(default_timeout)))
    try:
        args = parser.parse_args()
        args.user = unique(args.user)
        return args
    except argparse.ArgumentTypeError as err:
        prologue()
        print()
        error(err)
        sys.exit(1)


def generate_users(target, profile, quiet=False):
    users = [target]
    for op in profile:
        temp = []
        for user in users:
            for user1 in op.apply(user):
                if user1 not in set(users + temp):
                    temp.append(user1)
                    success(user1, quiet)
        users.extend(temp)
    users.remove(target)
    return users


def generate_all(targets, profile, quiet=False):
    info('generating usernames ...', quiet)
    users = []
    for target in targets:
        users.extend(generate_users(target, profile, quiet))
    total = len(users)
    info('generated ' + str(total) + ' username'
         + ('' if total == 1 else 's'), quiet)
    return users


def user_available(user, session, timeout=default_timeout, quiet=False):
    try:
        resp = session.get(endpoint_url + user, timeout=timeout).json()
        if 'valid' in resp:
            return resp['valid']
        error('malformed response: ' + str(resp))
    except (requests.exceptions.RequestException, json.JSONDecodeError) as err:
        error(err)


def check_available(users, threads=default_threads, retries=default_retries,
                    timeout=default_timeout, quiet=False):
    info('checking availability ...', quiet)
    hits = 0
    errs = 0
    checked = 0
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        with requests.session() as session:
            session.mount('https://twitter.com',
                          requests.adapters.HTTPAdapter(max_retries=retries))
            futures = {pool.submit(user_available, user, session,
                                   timeout, quiet): user for user in users}
            try:
                for future in concurrent.futures.as_completed(futures):
                    user = futures[future]
                    available = future.result()
                    if available:
                        hits += 1
                        success(user + ' is available', quiet)
                        results.append(user + ',1')
                    elif available is not None:
                        failure(user + ' is unavailable', quiet)
                        results.append(user + ',0')
                    else:
                        errs += 1
                        results.append(user + ',-1')
                    checked += 1
            except KeyboardInterrupt:
                print('  stopping ...')
                for future in futures:
                    future.cancel()
    total = len(users)
    msg = (str(hits) + ' out of ' + str(total) + ' username'
           + (' is' if total == 1 else 's are') + ' available')
    caveat = []
    if checked != total:
        caveat.append('stopped after ' + str(checked) + ' check'
                      + ('' if checked == 1 else 's'))
    if errs:
        caveat.append('with ' + str(errs) + ' error'
                      + ('' if errs == 1 else 's'))
    info(msg + (' (' + ' '.join(caveat) + ')' if caveat else ''), quiet)
    return results


def write_csv(lines, outfile, quiet=False):
    info('outputing results ...', quiet)
    outfile.write(os.linesep.join(lines))


def main():
    args = parse_args()
    prologue(args.quiet)
    users = generate_all(args.user, args.profile, args.quiet)
    if args.check and len(users) > 0:
        users = check_available(users, args.threads, args.retries,
                                args.timeout, args.quiet)
    if args.output:
        write_csv(users, args.output, args.quiet)
        args.output.close()
    info('done', args.quiet)


if __name__ == '__main__':
    main()
