#! env python3
# this scripts was used with binaryninja version 2.2.2598-dev Personal

import binaryninja
import time
import re


def function_from_name(bv, name):
    function_syms = bv.get_symbols_by_name(name)
    assert len(function_syms) == 1

    function_sym = function_syms[0]
    assert function_sym.type == binaryninja.enums.SymbolType.FunctionSymbol

    return bv.get_function_at(function_sym.address)


def change_lhs_rhs_syntax(line):
    r = r'.*\*\(arg1 \+ (?P<index>.*?)\)'
    m = re.match(r, line)
    while m is not None:
        index = m.group('index')
        line = line.replace('*(arg1 + {})'.format(index), 'arg1_{}'.format(index))
        m = re.match(r, line)

    r = '.*sx\.d\((?P<inner>.*?)\)'
    m = re.match(r, line)
    while m is not None:
        inner = m.group('inner')
        line = line.replace('sx.d({})'.format(inner), inner)
        m = re.match(r, line)

    r = '.*\((?P<inner>.*?)\).b'
    m = re.match(r, line)
    while m is not None:
        inner = m.group('inner')
        line = line.replace('({}).b'.format(inner), inner)
        m = re.match(r, line)

    line = line.replace('s>>', '>>')
    line = line.replace('*arg1', 'arg1_0')
    line = line.replace('arg1', 'flag')

    return line


def analyze(bv, current_function, last_function):
    if current_function.start == last_function.start:
        return

    lines = list()
    for block in current_function.high_level_il:
        for instruction in block:
            for line in instruction.lines:
                lines.append(str(line))

    # the code is very simple
    # there is an if statement which must be true
    # there is a call to a function, for which the return value must be true

    # before we start, expand variables
    variables = dict()
    assignment_statement = r'^[a-z]* (?P<name>[a-z0-9_]*) = (?P<value>.*)$'
    expanded_lines = list()
    for line in lines:
        m = re.match(assignment_statement, line)
        if m is not None:
            variables[m.group('name')] = m.group('value')
        else:
            expanded_line = line
            for name, value in variables.items():
                expanded_line = expanded_line.replace(name, value)
            expanded_lines.append(expanded_line)
    lines = expanded_lines

    # find the first condition
    condition_lhs = None
    condition = None
    condition_rhs = None
    for line in lines:
        m = re.match(r'^if \((?P<condition_lhs>.*) (?P<condition>[s=><]*?) (?P<condition_rhs>.*)\)$', line)
        if m is not None:
            condition_lhs = m.group('condition_lhs')
            condition = m.group('condition')
            condition_rhs = m.group('condition_rhs')
            break

    # validate assumption used in regex
    assert condition_lhs is not None
    assert condition is not None
    assert condition_rhs is not None

    # change condition_lhs and condition_rhs to use array indexing syntax
    condition_lhs = change_lhs_rhs_syntax(condition_lhs)
    condition = condition.replace('s', '')
    condition_rhs = change_lhs_rhs_syntax(condition_rhs)

    # find function call
    function_name = None
    for line in lines:
        m = re.match(r'^.* = func_(?P<function_name>[0-9a-f]*)\(arg1\)$', line)
        if m is not None:
            function_name = 'func_' + m.group('function_name')

    # validate assumption used in regex
    assert function_name is not None

    print('{:s} - {:60s} {:5s} {:s}'.format(current_function.name, condition_lhs, condition, condition_rhs))

    analyze(bv, function_from_name(bv, function_name), last_function)


def solution(bv):
    first_function = function_from_name(bv, 'func_1ef462fb1a985242d6ac0c03891f65b3')
    last_function = function_from_name(bv, 'func_50eec6aa5225354783e1d705e2c319da')
    analyze(bv, first_function, last_function)
