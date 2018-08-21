import claripy
import sys
import logging

logger = logging.getLogger('WinConditionTracker')
logger.setLevel(logging.ERROR)

def check_input(state, values, fd):
    if values == 'printable':
        ranges = [['!', '~']]
    elif values == 'alphanumeric':
        ranges = [['0', '9'], ['A', 'Z'], ['a', 'z']]
    elif values == 'letters':
        ranges = [['A', 'Z'], ['a', 'z']]
    elif values == 'zero-bytes':
        ranges = [['\0', '\0']]
    elif values == 'ascii':
        ranges = [['\0', '\x7f']]
    elif values == 'any':
        return state
    else:
        logger.error('Invalid input constraint')
        sys.exit(-1)


    stdin = state.posix.get_fd(fd).all_bytes().chop(8)
    constraints = claripy.And()
    for c in stdin:
        constraint = claripy.And()
        for r in ranges:
            constraint = claripy.And(c >= r[0], c <= r[1], constraint)
        constraints = claripy.And(constraint, constraints)
    if state.solver.satisfiable(extra_constraints=[constraints]):
        state.add_constraints(constraints)
        return state
    else:
        return None

def constrain_input(state, stdin, values):
    if values == 'printable':
        ranges = [['!', '~']]
    elif values == 'alphanumeric':
        ranges = [['0', '9'], ['A', 'Z'], ['a', 'z']]
    elif values == 'letters':
        ranges = [['A', 'Z'], ['a', 'z']]
    elif values == 'zero-bytes':
        ranges = [['\0', '\0']]
    elif values == 'ascii':
        ranges = [['\0', '\x7f']]
    elif values == 'any':
        return state
    else:
        logger.error('Invalid input constraint')
        sys.exit(-1)

    constraints = claripy.And()
    for c in stdin:
        constraint = claripy.And()
        for r in ranges:
            constraint = claripy.And(c >= r[0], c <= r[1], constraint)
        constraints = claripy.And(constraint, constraints)
    if state.solver.satisfiable(extra_constraints=[constraints]):
        state.add_constraints(constraints)
        return state
    else:
        return None
