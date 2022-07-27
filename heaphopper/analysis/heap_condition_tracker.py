from angr import SimProcedure
from angr.state_plugins import SimStatePlugin, inspect
import claripy
import logging

logger = logging.getLogger('HeapConditionTracker')


class HeapConditionTracker(SimStatePlugin):
    def widen(self, _others):
        pass

    def __init__(self, config=None, libc=None, allocator=None, initialized=0, vulnerable=False, vuln_state=None,
                 vuln_type='', malloc_dict=None, free_dict=None, write_bps=None, wtarget=None,
                 req_size=None, arb_write_info=None, double_free=None, fake_frees=None, stack_trace=None,
                 ctrl_data_idx=0, curr_freed_chunk=None, sym_data_states=None, sym_data_size=None, **kwargs):  # pylint:disable=unused-argument
        super(HeapConditionTracker, self).__init__()
        self.config = config
        self.libc = libc
        self.allocator = allocator
        self.initialized = initialized
        self.vulnerable = vulnerable
        self.vuln_state = vuln_state
        self.vuln_type = vuln_type
        self.malloc_dict = dict() if malloc_dict is None else dict(malloc_dict)
        self.free_dict = dict() if free_dict is None else dict(free_dict)
        self.double_free = list() if double_free is None else list(double_free)
        self.fake_frees = list() if fake_frees is None else list(fake_frees)
        self.write_bps = list() if write_bps is None else list(write_bps)
        self.wtarget = wtarget
        self.req_size = req_size
        self.arb_write_info = dict() if arb_write_info is None else dict(arb_write_info)
        # Stack-trace of arb-write
        self.stack_trace = list() if stack_trace is None else list(stack_trace)
        # Counter for malloc dests
        self.ctrl_data_idx = ctrl_data_idx
        # Current object passed to free info
        self.curr_freed_chunk = curr_freed_chunk
        self.sym_data_states = dict() if sym_data_states is None else dict(sym_data_states)
        self.sym_data_size = sym_data_size

    def set_level(self, level): # pylint:disable=no-self-use
        logger.setLevel(level)

    @SimStatePlugin.memo
    def copy(self, _memo):
        return HeapConditionTracker(**self.__dict__)

    #def set_state(self, s, **kwargs):
    #    super(HeapConditionTracker, self).set_state(s, **kwargs)

    # we need that for veritesting
    def merge(self, others, merge_conditions, common_ancestor=None): # pylint:disable=unused-argument
        # TODO: Do better merging
        for o in others:
            self.vulnerable |= o.vulnerable

            if not self.vuln_type and o.vuln_type:
                self.vuln_type = o.vuln_type

            if not self.malloc_dict and o.malloc_dict:
                self.malloc_dict = dict(o.malloc_dict)

            if not self.free_dict and o.free_dict:
                self.free_dict = dict(o.free_dict)

            if not self.arb_write_info and o.arb_write_info:
                self.arb_write_info = dict(o.arb_write_info)

            if not self.write_bps and o.write_bps:
                self.write_bps = o.write_bps

            if not self.wtarget and o.wtarget:
                self.wtarget = o.wtarget

            if not self.req_size and o.req_size:
                self.req_size = o.req_size

            if not self.double_free and o.double_free:
                self.double_free = list(o.double_free)

            if not self.vuln_state and o.vuln_state:
                self.vuln_state = o.vuln_state.copy()

            if not self.fake_frees and o.fake_frees:
                self.fake_frees = list(o.fake_frees)

            if not self.stack_trace and o.stack_trace:
                self.stack_trace = list(o.stack_trace)

            if not self.ctrl_data_idx and o.ctrl_data_idx:
                self.ctrl_data_idx = o.ctrl_data_idx

            if o.initialized:
                self.initialized = o.initialized

            return True


class MallocInspect(SimProcedure):
    IS_FUNCTION = True
    local_vars = ()

    def run(self, size, malloc_addr=None, vulns=None, ctrl_data=None): # pylint: disable=arguments-differ,unused-argument
        if 'arb_write' in vulns:
            self.state.heaphopper.write_bps.append(self.state.inspect.b('mem_write', when=inspect.BP_BEFORE,
                                                            action=check_write))
        self.state.heaphopper.req_size = size
        self.call(malloc_addr, (size,), 'check_malloc', prototype='void *malloc(size_t)')

    def check_malloc(self, size, malloc_addr, vulns=None, ctrl_data=None): #pylint:disable=unused-argument
        # Clear breakpoints
        for bp in self.state.heaphopper.write_bps:
            self.state.inspect.remove_breakpoint('mem_write', bp=bp)
        self.state.heaphopper.write_bps = []

        # Don't track heap_init malloc
        if self.state.heaphopper.initialized == 0:
            self.state.heaphopper.initialized = 1
            return self.state.regs.rax

        if 'arb_write' in vulns:
            # Remove breakpoint and check for arbitrary writes
            if self.state.heaphopper.vuln_type == 'arbitrary_write':
                #logger.info('Found arbitrary write')
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_type = 'arbitrary_write_malloc'

        # Check if malloc return some bogus pointer
        addr = self.state.regs.rax

        # Get ctrl_data ptr used as id
        dict_key = ctrl_data[self.state.heaphopper.ctrl_data_idx]
        self.state.heaphopper.ctrl_data_idx += 1

        # This might be better than checking for symbolic
        sols = self.state.solver.eval_upto(addr, 2)
        if len(sols) > 1:
            return self.check_sym_malloc(addr, vulns, dict_key)

        # Get min val
        val = sols[0]
        self.state.add_constraints(addr == val)

        if self.state.heaphopper.vulnerable:
            return val

        if 'bad_alloc' in vulns and val in self.state.heaphopper.fake_frees:
            logger.info('Found allocation to fake freed address')
            self.state.add_constraints(addr == val)
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'malloc_non_heap'
            self.state.heaphopper.vuln_state = self.state.copy()
        elif 'bad_alloc' in vulns and val < self.state.heap.heap_base:
            logger.info('Found allocation on bogus non-heap address')
            self.state.add_constraints(addr < self.state.heap.heap_base)
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'malloc_non_heap'
            self.state.heaphopper.vuln_state = self.state.copy()
        elif 'overlap_alloc' in vulns and val not in self.state.heaphopper.double_free:
            if self.check_overlap(self.state.heaphopper.malloc_dict, addr, self.state.heaphopper.req_size):
                return val

        self.state.heaphopper.malloc_dict[dict_key] = (self.state.heaphopper.req_size, addr)

        # Remove from free dict if reallocated
        for key in list(self.state.heaphopper.free_dict.keys()):
            sol = self.state.solver.min(self.state.heaphopper.free_dict[key][1])
            if val == sol:
                self.state.heaphopper.free_dict.pop(key)
                break

        return val

    def check_sym_malloc(self, addr, vulns, dict_key):
        if self.state.heaphopper.vulnerable:
            return addr

        # check non-heap:
        if 'bad_alloc' in vulns and self.state.solver.satisfiable(
                extra_constraints=[addr < self.state.heap.heap_base]):
            logger.info('Found allocation on bogus non-heap address')
            self.state.add_constraints(addr < self.state.heap.heap_base)
            val = self.state.solver.eval(addr)
            self.state.add_constraints(addr == val)
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'malloc_non_heap'
            self.state.heaphopper.vuln_state = self.state.copy()
            return addr

        # check overlaps
        # if the ast grows to big, str(addr) is expensive
        logger.info("check_sym_malloc: addr.ast.depth = %d", addr.to_claripy().depth)
        if 'overlap_alloc' in vulns and (addr.to_claripy().depth > 30 or \
                str(addr) not in self.state.heaphopper.double_free):
            if self.check_overlap(self.state.heaphopper.malloc_dict, addr, self.state.heaphopper.req_size):
                return addr

        val = self.state.solver.min(addr)

        self.state.heaphopper.malloc_dict[dict_key] = (self.state.heaphopper.req_size, addr)

        ## This improves speed significantly, nobody knows why... some magic caching probably
        #size_vals = self.state.solver.eval_upto(self.state.heaphopper.req_size, 16)
        ## Let's use the value for smth. useful, if we solve anyways
        #if len(size_vals) == 1:
        #    self.state.add_constraints(self.state.heaphopper.req_size == size_vals[0])

        # Remove from free dict if reallocated
        for key in list(self.state.heaphopper.free_dict.keys()):
            sol = self.state.solver.min(self.state.heaphopper.free_dict[key][1])
            if val == sol:
                self.state.heaphopper.free_dict.pop(key)
                break

        return addr

    def check_overlap(self, malloc_dict, addr, req_size):
        for dst in list(malloc_dict.keys()):
            alloc = malloc_dict[dst][1]
            condition1 = self.state.solver.And(alloc < addr, alloc + malloc_dict[dst][0] > addr)
            condition2 = self.state.solver.And(alloc > addr, addr + req_size > alloc)
            if self.state.solver.satisfiable(extra_constraints=[condition1]):
                logger.info('Found overlapping allocation')
                self.state.add_constraints(condition1)
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_type = 'malloc_allocated'
                self.state.heaphopper.vuln_state = self.state.copy()
                return True
            if self.state.solver.satisfiable(extra_constraints=[condition2]):
                logger.info('Found overlapping allocation')
                self.state.add_constraints(condition2)
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_type = 'malloc_allocated'
                self.state.heaphopper.vuln_state = self.state.copy()
                return True
        return False


class FreeInspect(SimProcedure):
    IS_FUNCTION = True

    def run(self, ptr, free_addr=None, vulns=None, sym_data=None): # pylint: disable=arguments-differ
        val = self.state.solver.min(ptr)
        if val in sym_data:
            self.state.heaphopper.fake_frees.append(val)
        else:
            found = False
            for key in list(self.state.heaphopper.malloc_dict.keys()):
                sol = self.state.solver.min(self.state.heaphopper.malloc_dict[key][1])
                if val == sol:
                    minfo = self.state.heaphopper.malloc_dict.pop(key)
                    self.state.heaphopper.free_dict[key] = minfo
                    found = True
            if not found:
                for key in list(self.state.heaphopper.free_dict.keys()):
                    sol = self.state.solver.min(self.state.heaphopper.free_dict[key][1])
                    if val == sol:
                        self.state.heaphopper.double_free.append(val)

        if 'arb_write' in vulns:
            self.state.heaphopper.write_bps.append(self.state.inspect.b('mem_write', when=inspect.BP_BEFORE,
                                                            action=check_write))

        if val in sym_data:
            self.state.heaphopper.write_bps.append(self.state.inspect.b('mem_write', when=inspect.BP_BEFORE,
                                                            action=check_sym_data))
        self.state.heaphopper.curr_freed_chunk = val

        self.call(free_addr, [ptr], 'check_free', prototype='void free(void*)')

    def check_free(self, ptr, free_addr, vulns=None, sym_data=None): #pylint:disable=unused-argument
        # Clear the chunk currently being freed
        self.state.curr_freed_chunk = None

        # Clear breakpoints
        for bp in self.state.heaphopper.write_bps:
            self.state.inspect.remove_breakpoint('mem_write', bp=bp)
        self.state.heaphopper.write_bps = []

        # Don't track heap_init free
        if self.state.heaphopper.initialized == 1:
            self.state.heaphopper.initialized = 2
            return

        # check non-heap:
        if 'bad_free' in vulns and self.state.solver.satisfiable(
                extra_constraints=[ptr < self.state.heap.heap_base]):
            logger.info('Found free of non-heap address')
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'free_non_heap'
            self.state.heaphopper.vuln_state = self.state.copy()
            return

        if 'double_free' in vulns:
            val = self.state.solver.min(ptr)
            if val in self.state.heaphopper.double_free:
                logger.info('Found double free')
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_state = self.state.copy()
                return

        if 'arb_write' not in vulns:
            return

        # Remove breakpoint and check for arbitrary writes
        if self.state.heaphopper.vuln_type == 'arbitrary_write':
            #logger.info('Found arbitrary write')
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'arbitrary_write_free'

        return


def check_write(state):
    # If we found an arb_write we're done
    if state.heaphopper.vuln_type.startswith('arbitrary_write'):
        return

    # Check if we have an arbitrary_write
    addr = state.inspect.mem_write_address
    val = state.inspect.mem_write_expr
    #logger.debug('check_write: addr: %s' % addr)
    #logger.debug('check_write: val: %s' % val)
    constr = claripy.And(addr >= state.heaphopper.wtarget[0],
                         addr < state.heaphopper.wtarget[0] + state.heaphopper.wtarget[1])

    if state.solver.satisfiable(extra_constraints=[constr]):
        #logger.debug('check_write: Found arbitrary write')
        state.add_constraints(constr)
        state.heaphopper.vuln_state = state.copy()
        state.heaphopper.arb_write_info = dict(instr=state.addr, addr=addr, val=val)
        state.heaphopper.vuln_type = 'arbitrary_write'
        state.heaphopper.stack_trace = get_libc_stack_trace(state)

def check_sym_data(state):
    # Check if we overwrite a sym_data structure passed to free
    addr = state.inspect.mem_write_address
    free_addr = state.heaphopper.curr_freed_chunk
    if free_addr in state.heaphopper.sym_data_states and not state.heaphopper.sym_data_states[free_addr]:
        #logger.debug('check_sym_data: curr_freed_chunk: 0x%x' % free_addr)
        #logger.debug('check_sym_data: addr: %s' % addr)
        constr = claripy.And(addr >= free_addr, addr < free_addr + state.heaphopper.sym_data_size)
        if not state.solver.symbolic(addr) and state.solver.satisfiable(extra_constraints=[constr]):
            #logger.debug('check_sym_data: Saving state')
            state.heaphopper.sym_data_states[free_addr] = state.copy()




def get_libc_stack_trace(state):
    backtrace = state.history.bbl_addrs.hardcopy[::-1]
    index = 0
    while state.heaphopper.allocator.contains_addr(backtrace[index]):
        index += 1
    return backtrace[:index]
