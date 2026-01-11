import logging
import os
import time
import psutil
from multiprocessing import Pool
from .iocg import InterObjectCallgraph
from .lmd import LibMatchDescriptor
from .functiondiff import FunctionDiff, FunctionDiffResult
from collections import defaultdict

l = logging.getLogger("bdsig.libmatch")


def _get_mem_gb():
    """Get USS (Unique Set Size) memory in GB - most accurate for this process."""
    try:
        return psutil.Process().memory_full_info().uss / (1024**3)
    except (AttributeError, psutil.AccessDenied):
        return psutil.Process().memory_info().rss / (1024**3)


class PerformanceTracker:
    """Track performance metrics for each phase of libmatch."""

    def __init__(self):
        self.phases = {}
        self.start_time = time.time()
        self.start_cpu = psutil.Process().cpu_times()

    def _get_mem_gb(self):
        """Get USS (Unique Set Size) memory in GB - most accurate."""
        try:
            return psutil.Process().memory_full_info().uss / (1024**3)
        except (AttributeError, psutil.AccessDenied):
            return psutil.Process().memory_info().rss / (1024**3)

    def start_phase(self, phase_name):
        """Start tracking a phase."""
        mem_gb = self._get_mem_gb()
        cpu_times = psutil.Process().cpu_times()
        self.phases[phase_name] = {
            'start_time': time.time(),
            'start_mem_gb': mem_gb,
            'start_cpu_user': cpu_times.user,
            'start_cpu_system': cpu_times.system,
            'end_time': None,
            'duration': None,
            'work_items': 0,
            'matches': 0,
        }
        l.info(f"[PERF] Phase '{phase_name}' started | Mem: {mem_gb:.2f} GB")

    def end_phase(self, phase_name, work_items=0, matches=0):
        """End tracking a phase and log results."""
        if phase_name not in self.phases:
            l.info(f"[PERF] Phase '{phase_name}' was not started")
            return

        phase = self.phases[phase_name]
        phase['end_time'] = time.time()
        phase['duration'] = phase['end_time'] - phase['start_time']
        phase['work_items'] = work_items
        phase['matches'] = matches

        mem_gb = self._get_mem_gb()
        cpu_times = psutil.Process().cpu_times()

        phase['end_mem_gb'] = mem_gb
        phase['mem_delta_mb'] = (mem_gb - phase['start_mem_gb']) * 1024
        phase['cpu_user_delta'] = cpu_times.user - phase['start_cpu_user']
        phase['cpu_system_delta'] = cpu_times.system - phase['start_cpu_system']
        phase['cpu_total_delta'] = phase['cpu_user_delta'] + phase['cpu_system_delta']

        # Calculate throughput
        throughput = work_items / phase['duration'] if phase['duration'] > 0 and work_items > 0 else 0

        l.info(f"[PERF] Phase '{phase_name}' completed:")
        l.info(f"[PERF]   Duration: {phase['duration']:.2f}s")
        l.info(f"[PERF]   Memory: {mem_gb:.2f} GB (delta: {phase['mem_delta_mb']:+.0f} MB)")
        l.info(f"[PERF]   CPU time: {phase['cpu_total_delta']:.2f}s (user: {phase['cpu_user_delta']:.2f}s, sys: {phase['cpu_system_delta']:.2f}s)")
        if work_items > 0:
            l.info(f"[PERF]   Work items: {work_items:,} | Throughput: {throughput:,.0f}/s")
        if matches > 0:
            l.info(f"[PERF]   Matches found: {matches:,}")

    def log_progress(self, phase_name, processed, total, matches=0):
        """Log progress during a phase."""
        if phase_name not in self.phases:
            return

        phase = self.phases[phase_name]
        elapsed = time.time() - phase['start_time']
        rate = processed / elapsed if elapsed > 0 else 0
        eta = (total - processed) / rate if rate > 0 else 0
        pct = 100.0 * processed / total if total > 0 else 0

        mem_gb = self._get_mem_gb()
        l.info(f"[PERF] {phase_name}: {processed:,}/{total:,} ({pct:.1f}%) | {rate:,.0f}/s | ETA: {eta:.0f}s | Matches: {matches:,} | Mem: {mem_gb:.2f} GB")

    def log_summary(self):
        """Log performance summary using the logger."""
        total_duration = time.time() - self.start_time
        cpu_times = psutil.Process().cpu_times()
        total_cpu = (cpu_times.user - self.start_cpu.user) + (cpu_times.system - self.start_cpu.system)
        mem_gb = self._get_mem_gb()

        l.info("=" * 70)
        l.info("LIBMATCH PERFORMANCE SUMMARY")
        l.info("=" * 70)
        l.info(f"Total wall time: {total_duration:.2f}s ({total_duration/60:.2f} min)")
        l.info(f"Total CPU time: {total_cpu:.2f}s")
        l.info(f"CPU efficiency: {100*total_cpu/total_duration:.1f}%" if total_duration > 0 else "N/A")
        l.info(f"Final memory: {mem_gb:.2f} GB")
        l.info("-" * 70)
        l.info(f"{'Phase':<25} {'Duration':>10} {'Work Items':>12} {'Rate':>10} {'Matches':>10}")
        l.info("-" * 70)

        for phase_name, phase in self.phases.items():
            if phase['duration'] is not None:
                duration_str = f"{phase['duration']:.2f}s"
                work_str = f"{phase['work_items']:,}" if phase['work_items'] > 0 else "-"
                rate = phase['work_items'] / phase['duration'] if phase['duration'] > 0 and phase['work_items'] > 0 else 0
                rate_str = f"{rate:,.0f}/s" if rate > 0 else "-"
                matches_str = f"{phase['matches']:,}" if phase['matches'] > 0 else "-"
                l.info(f"{phase_name:<25} {duration_str:>10} {work_str:>12} {rate_str:>10} {matches_str:>10}")

        l.info("=" * 70)


# Global performance tracker
_perf_tracker = None


def _get_perf_tracker():
    """Get or create the global performance tracker."""
    global _perf_tracker
    if _perf_tracker is None:
        _perf_tracker = PerformanceTracker()
    return _perf_tracker



# Global references for worker processes (set during worker init)
# This avoids pickling large LMD objects for every work item
_binary_lmd = None
_lib_lmds = {}
_addr_bounds = {}  # Cache address bounds to avoid touching loader objects


def _init_worker(binary_lmd, lib_lmds_dict, addr_bounds):
    """
    Initialize worker process with shared data.
    Called ONCE per worker when Pool is created (not per work item).
    Uses fork() Copy-on-Write to share memory efficiently.

    addr_bounds: dict mapping lmd_id -> (min_addr, max_addr) to avoid loader access
    """
    global _binary_lmd, _lib_lmds, _addr_bounds
    _binary_lmd = binary_lmd
    _lib_lmds = lib_lmds_dict
    _addr_bounds = addr_bounds


def _compute_function_diff_worker(args):
    """
    Worker function - receives only lightweight tuple.
    Uses global _binary_lmd and _lib_lmds set during worker init.

    :param args: Tuple of (lmd_id, binary_faddr, lib_faddr) - just 3 integers!
    :returns: Tuple of (binary_faddr, lib_faddr, fd, lmd_id) if probably_identical, else None
    """
    global _binary_lmd, _lib_lmds, _addr_bounds
    lmd_id, binary_faddr, lib_faddr = args

    try:
        lib_lmd = _lib_lmds[lmd_id]
        bin_func = _binary_lmd.normalized_functions[binary_faddr]
        lib_func = lib_lmd.normalized_functions[lib_faddr]
        # Pass pre-computed address bounds to avoid touching loader objects (reduces COW)
        fd = FunctionDiff(
            _binary_lmd, lib_lmd, bin_func, lib_func,
            addr_bounds_a=_addr_bounds.get('binary'),
            addr_bounds_b=_addr_bounds.get(lmd_id)
        )
        if fd.probably_identical:
            # Return lightweight FunctionDiffResult (~2-3KB) instead of FunctionDiff (~14MB)
            # This prevents memory leak in multiprocessing by breaking references to NormalizedFunction
            return (binary_faddr, lib_faddr, FunctionDiffResult(fd), lmd_id)
        return None
    except Exception as e:
        l.error(f"Error processing function pair ({binary_faddr:#08x}, {lib_faddr:#08x}): {e}")
        return None


class LibMatch(object):
    def __init__(self, binary_lmd, lmdb, jobs=None):
        """
        :param binary_lmd: The LibMatchDescriptor of the target binary
        :param lmdb: LibMatchDatabase containing library LMDs
        :param jobs: Number of parallel workers (None for auto-detect, 1 for sequential)
        """
        self.binary_lmd = binary_lmd
        self.lmdb = lmdb
        self.ambiguous_funcs = []
        self._first_order_matches = defaultdict()
        self._second_order_matches = defaultdict()

        # Set up parallelization
        if jobs is None:
            # Auto-detect: use min(16, CPU count)
            self._jobs = min(16, os.cpu_count() or 8)
        else:
            self._jobs = jobs

        self._compute()

    @classmethod
    def _first_order_heuristic(self, lib_attrs, bin_attrs):
        """
        The heuristic to use to determine whether or not a given tuple of attrs from a lib func
        should match with a given tuple of attrs from a bin func.
        """
        # TODO: perfect matching
        return lib_attrs == bin_attrs

    def _compute_first_order_matches(self, lib_name, lib_lmds):
        """
        Find matches between a lib and the target binary based purely on function attribute tuples.
        Now includes additional filtering heuristics to reduce Phase 2 workload.
        """
        self._first_order_matches[lib_name] = {}
        for lmd in lib_lmds:
            self._first_order_matches[lib_name][lmd] = {}

            for faddr in lmd.viable_functions:
                # match the lib func against the binary if the first order heuristic passes
                attrs = lmd.function_attributes[faddr]
                results = set()
                #results = {bin_faddr for bin_faddr, bin_attrs in self.binary_lmd.function_attributes.items()
                #           if self._first_order_heuristic(attrs, bin_attrs)}
                for bin_faddr, bin_attrs in self.binary_lmd.function_attributes.items():
                    if faddr == 0x4002bd and bin_faddr == 0x00003D45:
                        import ipdb; ipdb.set_trace()
                    if self._first_order_heuristic(attrs, bin_attrs):
                        # Additional filtering: Skip if attributes are too different
                        # attrs = (num_blocks, num_edges, num_calls)
                        num_blocks_lib, num_edges_lib, num_calls_lib = attrs
                        num_blocks_bin, num_edges_bin, num_calls_bin = bin_attrs

                        # Skip if dramatically different sizes (more than 2x difference)
                        # This helps filter out obviously wrong matches
                        if num_blocks_lib > 0 and num_blocks_bin > 0:
                            if num_blocks_lib > 2 * num_blocks_bin or num_blocks_bin > 2 * num_blocks_lib:
                                continue

                        results.add(bin_faddr)
                self._first_order_matches[lib_name][lmd][faddr] = results

    @classmethod
    def _second_order_heuristic(cls, binary_lmd, lib_lmd, binary_faddr, lib_faddr):
        """
        The heuristic to use to determine whether or not two functions are approximately the same
        based on the FunctionDiff implementation.
        """
        lib_func = lib_lmd.normalized_functions[lib_faddr]
        bin_func = binary_lmd.normalized_functions[binary_faddr]
        # TODO: perfect matching
        return FunctionDiff(binary_lmd, lib_lmd, bin_func, lib_func)

    def _compute_second_order_matches(self, lib_name):
        """
        Refine matches between a lib and the target binary based purely on the FunctionDiff method.
        Sequential version (original).
        """
        self._second_order_matches[lib_name] = {}
        for lmd, lmd_matches in self._first_order_matches[lib_name].items():
            self._second_order_matches[lib_name][lmd] = {}
            for faddr, func_matches in lmd_matches.items():
                self._second_order_matches[lib_name][lmd][faddr] = []
                for maddr in func_matches:
                    fd = self._second_order_heuristic(self.binary_lmd, lmd, maddr, faddr)
                    if fd.function_a.name == "tcp_recved" and fd.function_b.name == 'tcp_recved':
                        import ipdb;
                        ipdb.set_trace()
                    if fd.probably_identical:
                        self._second_order_matches[lib_name][lmd][faddr].append((maddr, fd))

    def _compute_second_order_matches_parallel(self, lib_name):
        """
        Refine matches between a lib and the target binary using parallel FunctionDiff computation.
        Uses worker initialization pattern to avoid pickling large LMD objects per work item.
        LMDs are passed ONCE during Pool creation via initializer, not per work item.
        """
        self._second_order_matches[lib_name] = {}

        # Build LMD lookup dictionary (id -> lmd object)
        # This allows work items to reference LMDs by ID instead of passing the full object
        lib_lmds_dict = {}
        work_items = []

        for lmd, lmd_matches in self._first_order_matches[lib_name].items():
            lmd_id = id(lmd)
            lib_lmds_dict[lmd_id] = lmd
            self._second_order_matches[lib_name][lmd] = {}

            for faddr, func_matches in lmd_matches.items():
                self._second_order_matches[lib_name][lmd][faddr] = []
                for maddr in func_matches:
                    # Work item is now just 3 integers (~24 bytes, not 9.8GB!)
                    work_items.append((lmd_id, maddr, faddr))

        if not work_items:
            return

        # Calculate optimal chunk size
        # Smaller chunks for better load balancing
        # More chunks = more even distribution when function complexity varies
        # With 14M items and 16 workers: ~8,750 chunks of ~1,600 items each
        chunk_size = max(100, min(2000, len(work_items) // (self._jobs * 100)))

        l.info(f"Phase 2: Processing {len(work_items)} function pairs with {self._jobs} workers (chunk_size={chunk_size})")

        # Pre-compute address bounds to avoid workers touching loader objects (reduces COW memory)
        addr_bounds = {'binary': (self.binary_lmd.loader.min_addr, self.binary_lmd.loader.max_addr)}
        for lmd_id, lmd in lib_lmds_dict.items():
            addr_bounds[lmd_id] = (lmd.loader.min_addr, lmd.loader.max_addr)

        # Process in parallel with worker initialization
        # LMDs are passed ONCE per worker during Pool creation (via fork() COW)
        results = []
        start_time = time.time()
        processed = 0
        log_interval = max(1000, len(work_items) // 20)  # Log every 5% or 1000 items

        with Pool(
            processes=self._jobs,
            initializer=_init_worker,
            initargs=(self.binary_lmd, lib_lmds_dict, addr_bounds),
            maxtasksperchild=100  # Recycle workers after 100 chunks (~200K items) to release memory
        ) as pool:
            for result in pool.imap_unordered(
                _compute_function_diff_worker,
                work_items,
                chunksize=chunk_size
            ):
                processed += 1
                if result:
                    results.append(result)
                # Log progress periodically
                if processed % log_interval == 0:
                    elapsed = time.time() - start_time
                    rate = processed / elapsed if elapsed > 0 else 0
                    eta = (len(work_items) - processed) / rate if rate > 0 else 0
                    mem_gb = _get_mem_gb()
                    l.info(f"Phase 2: {processed}/{len(work_items)} ({100*processed/len(work_items):.1f}%) - {rate:.0f}/s - ETA {eta:.0f}s - {len(results)} matches - Mem: {mem_gb:.2f} GB")

        # Aggregate results into self._second_order_matches
        # Use lmd_id to look up actual lmd object from lib_lmds_dict
        for binary_faddr, lib_faddr, fd, lmd_id in results:
            lmd = lib_lmds_dict[lmd_id]
            self._second_order_matches[lib_name][lmd][lib_faddr].append((binary_faddr, fd))

        elapsed = time.time() - start_time
        l.info(f"Phase 2: Completed with {len(results)} matches in {elapsed:.1f}s ({len(work_items)/elapsed:.0f}/s)")

    def _postprocess_second_order_matches(self):

        # Gather the matches based on the functions in the original binary:
        matches = defaultdict(list)
        #for lib_res in self._second_order_matches:
        for lib_name, lib_matches in self._second_order_matches.items():
            for obj_lmd, obj_res in lib_matches.items():
                for obj_func_addr, obj_func_matches in obj_res.items():
                    if obj_func_matches:
                        for target_addr, match_info in obj_func_matches:
                            if len(matches[target_addr]) > 0:
                                # A collision! But is it a real one?
                                # Did we match better?
                                prev_lib, prev_lmd, prev_match_info = matches[target_addr][0]
                                if match_info.similarity_score > prev_match_info.similarity_score:
                                    # Better match
                                    matches[target_addr] = [(lib_name, obj_lmd, match_info)]
                                elif match_info.similarity_score == prev_match_info.similarity_score:
                                    matches[target_addr].append((lib_name, obj_lmd, match_info))
                                else:
                                    continue  # Worse match, ignore
                            else:
                                matches[target_addr].append((lib_name, obj_lmd, match_info))
        return matches

    def _compute_third_order(self):
        self._plain_matches = self._postprocess_second_order_matches()
        self._candidate_matches = self._postprocess_second_order_matches()
        for f_addr, matches in self._candidate_matches.items():
            if matches:
                self._narrow_third_order(f_addr, matches)

    def _compute_fourth_order(self):
        self.recursion_set = set()  # Issue #5: Use set for O(1) membership test and removal
        good_hits = []
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) == 1:
                good_hits.append((f_addr, matches,))
        for f_addr, matches in good_hits:
            self._narrow_fourth_order(f_addr, matches)

    def squish(self, func):
        """
        When resolving collisions, are all the collisions duplicates? If so, we probably don't care, and will handle it in post later
        (but we save the dupes for stats purposes)

        :return:
        """
        matches = self._candidate_matches[func]
        the_name = None
        if not matches:
            return
        for lib, lmd, fd in matches:
            if the_name is None:
                if isinstance(fd, str):
                    the_name = fd
                else:
                    the_name = fd.function_b.name
            if isinstance(fd, str) and the_name == fd:
                continue
            elif the_name == fd.function_b.name:
                continue
            else:
                return
        self._candidate_matches[func] = [matches[0]]

    recursion_set = set()  # Issue #5: Use set for O(1) membership test and removal

    def _narrow_third_order(self, f_addr, matches, exact_narrowing=False):
        # TODO: FIXME:
        # It's possible that you get a single match, and this match is good, but it's wrong, due to function call targets.
        # Maybe we should check everything, even if it has more than one match.
        # No match is better than one wrong one!
        if f_addr in self.recursion_set:
            l.debug("Oof, recursion to %#08x!" % f_addr)
            return
        self.recursion_set.add(f_addr)
        if len(matches) == 1:
            # Perfect match! cannot refine
            self.recursion_set.discard(f_addr)
            return
        l.debug("Analyzing function %#08x" % f_addr)
        # Get the target for each candidate match
        target_func = list(matches)[0][2].function_a
        target_callees = []
        for from_block, callees in target_func.call_sites.items():
            for callee in callees:
                if not self.binary_lmd.loader.main_object.contains_addr(callee):
                    # A jumpout! Fuck.
                    callee_name = "UnresolvableCallTarget"
                    target_callees.append({(callee, callee_name,)})
                elif callee in self.binary_lmd.banned_addrs:
                    callee_name = "Ignored"
                    target_callees.append({(callee, callee_name,)})
                elif callee not in self._candidate_matches or len(self._candidate_matches[callee]) == 0:
                    l.debug("Cannot disambiguate function at %#08x, unmatched call to %#08x" % (f_addr, callee))
                    self.ambiguous_funcs.append(f_addr)
                    self.recursion_set.discard(f_addr)
                    return  # We're fucked
                else:
                    callee_matches = self._candidate_matches[callee]
                    if len(callee_matches) > 1:
                        if callee == f_addr:
                            l.debug("Recursion is bad!")
                            continue
                        l.debug("Recursively resolving %#08x" % callee)
                        self._narrow_third_order(callee, callee_matches)
                        self.squish(callee)

                        if exact_narrowing and len(self._candidate_matches[callee]) > 1:
                            l.debug("Failed to narrow down call to %#08x" % callee)
                            self.ambiguous_funcs.append(f_addr)
                            self.recursion_set.discard(f_addr)
                            return
                    possible_callees = set  ()
                    for cm in callee_matches:
                        m_lib, m_lmd, m_fd = cm
                        callee_sym = m_lmd.symbol_for_addr(m_fd.function_b.addr)
                        if not callee_sym:
                            continue
                        callee_name = callee_sym.name
                        possible_callees.add((callee, callee_name,))
                    target_callees.append(possible_callees)
        if not target_callees:
            l.debug("No calls in function %#08x, cannot disambiguate" % f_addr)
            self.ambiguous_funcs.append(f_addr)
            return
        # For each possible match
        self._candidate_matches[f_addr] = []
        l.debug("Resolving Function %#08x" % f_addr)
        for lib_name, match_lmd, match_diff in matches:
            match_name = match_diff.function_b.name
            # Get the addresses of each function that library calls.
            lib_callees = []
            for lol in match_diff.function_b.call_sites.values():
                for lmao in lol:
                    lib_callees.append(lmao)
            # Here, we try to compare the functions we matched via direct block comparison with libraries, based on what we think
            # the target actually called.
            # However, we may not be able to accurately resolve the target's callees, so we check that, for each candidate
            # library function, its exact callees are in the set of potential callees in the target.
            # If not, we rule it out.
            for possible_targ_callees, lib_callee in zip(target_callees, lib_callees):
                if not possible_targ_callees:
                    continue
                try:
                    targ_callee_addr = list(possible_targ_callees)[0][0]
                    lib_callee_name = match_lmd.symbol_for_addr(lib_callee).name
                except:
                    l.debug("Hmm, something is wrong %#08x %#08x %s" % (f_addr, lib_callee, match_lmd.filename))
                    return
                for targ_callee in possible_targ_callees:
                    targ_callee_addr, targ_callee_name = targ_callee
                    if targ_callee_name == "Ignored":
                        l.debug("Ignoring unresolvable call to %#08x" % targ_callee_addr)
                        break
                    if targ_callee_name == lib_callee_name:
                        l.debug("\t\tMatched call to %s" % targ_callee_name)
                        break
                else:
                    l.debug("\tRuling out %s due to mismatched call to %#08x" % (lib_callee_name, targ_callee_addr))
                    break
            else:
                self._candidate_matches[f_addr].append((lib_name, match_lmd, match_diff))
                l.debug("Resolved call to %#08x to %s via callgraph" % (f_addr, match_name))
        self.recursion_set.discard(f_addr)

    def _narrow_fourth_order(self, f_addr, matches):
        """
        By now, we've probably matched a bunch of functions.  But we can't get them all.
        This will use those functions we could match to find the ones we can't.
        In contrast to the third phase, which uses callees to find callers, this does the opposite.
        For each function we can precisely match, collect the set of callees, and assign names to them based on the
        symbols in the source library.

        :param f_addr:
        :param matches:
        :return:
        """
        if f_addr in self.recursion_set:
            l.debug("Oof, recursion to %#08x!" % f_addr)
            return
        self.recursion_set.add(f_addr)
        if len(matches) != 1:
            self.recursion_set.discard(f_addr)
            return
        m_lib, m_lmd, m_fd = matches[0]
        if isinstance(m_fd, str):
            # We've already been here
            self.recursion_set.discard(f_addr)
            return
        target_func = m_fd.function_a
        lib_func = m_fd.function_b
        for (targ_block, targ_callees), (lib_block, lib_callees) in zip(target_func.call_sites.items(), lib_func.call_sites.items()):
           for targ_callee, lib_callee in zip(targ_callees, lib_callees):
                if not self.binary_lmd.loader.main_object.contains_addr(targ_callee):
                    # A jumpout! Fuck.
                    continue
                elif targ_callee in self.binary_lmd.banned_addrs:
                    # Junk.
                    continue
                elif targ_callee not in self._candidate_matches or len(self._candidate_matches[targ_callee]) == 0:
                    # Take a wild guess based on context
                    # Assuming the current match is correct, figure out what it would call in the original
                    # library and make that the name to match.
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if guessed_sym is None:
                        l.debug("No findable name for call to %#08x from %#08x(%s)"% (targ_callee, target_func.addr, lib_func.name))
                    else:
                        guessed_name = guessed_sym.name
                        l.debug("Guessing name of %#08x is %s due to call from %#08x(%s)" % (targ_callee, guessed_name, target_func.addr, lib_func.name))
                        self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                elif len(self._candidate_matches[targ_callee]) == 1:
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if guessed_sym is None:
                        l.debug("No findable name for call to %#08x from %#08x(%s)" % (
                        targ_callee, target_func.addr, lib_func.name))
                    else:
                        guessed_name = guessed_sym.name
                        lol, blah, fd = self._candidate_matches[targ_callee][0]
                        if isinstance(fd, str):
                            if fd == guessed_name:
                                continue
                        else:
                            if fd.function_b.name == guessed_name:
                                continue
                        l.debug("Guessing name of %#08x is %s due to call from %#08x(%s)" % (
                        targ_callee, guessed_name, target_func.addr, lib_func.name))
                        self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                    # Nothing to do
                    continue
                else:
                    # We have a collision.  Resolve it by picking the one with the matching
                    # name based on the lib's symbols
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if not guessed_sym:
                        l.debug("Couldn't figure out what %#08x is, called by func %#08x" % (lib_callee, lib_func.addr))
                        continue
                    guessed_name = guessed_sym.name
                    new_matches = []
                    for match in self._candidate_matches[targ_callee]:
                        c_lib, c_lmd, c_fd = match
                        if c_fd.function_b.name == guessed_name:
                            l.debug("Resolving %#08x to %s via call from %#08x(%s)" % (targ_callee, guessed_name, target_func.addr, lib_func.name))
                            new_matches.append((c_lib, c_lmd, c_fd,))
                    self._candidate_matches[targ_callee] = new_matches
                    if not new_matches:
                        # Welp, it really wasn't the other ones.
                        # Try something new instead
                        guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                        if guessed_sym is None:
                            l.debug("No findable name for call to %#08x from %#08x(%s)" % (
                                targ_callee, target_func.addr, lib_func.name))
                        else:
                            guessed_name = guessed_sym.name
                            l.debug("Guessing name of %#08x is %s due to call from %#08x(%s)" % (
                                    targ_callee, guessed_name, target_func.addr, lib_func.name))
                            self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                    self.squish(targ_callee)
                    if len(self._candidate_matches[targ_callee]) == 1:
                        # Recurse, see if that helps any.
                        l.debug("Recursively resolving %#08x" % targ_callee)
                        self._narrow_fourth_order(targ_callee, self._candidate_matches[targ_callee])
        self.recursion_set.discard(f_addr)

    def _dedup(self):
        """
        During all the previous phases, we'll make guesses, and all sorts of cool stuff.
        Now we have a bit of cleanup to do.  If we guessed a name for a function x, and a collision for
        function y includes the name of x, take it out of y's list, as we assume we can only have one copy of x in the binary
        THis means, by process of elimination, we may get even more matches!
        :return:
        """
        import copy
        good_hits = []
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) == 1:
                m_lib, m_lmd, m_fd = matches[0]
                if isinstance(m_fd, str):
                    # A guess has no fd
                    good_hits.append(m_fd)
                else:
                    good_hits.append(m_fd.function_b.name)
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) > 1:
                fixed_matches = copy.copy(matches)
                for match in matches:
                    m_lib, m_lmd, m_fd = match
                    if m_fd.function_b.name in good_hits:
                        l.debug("Removing %s from consideration for %#08x" % (m_fd.function_b.name, f_addr))
                        fixed_matches.remove(match)
                self._candidate_matches[f_addr] = fixed_matches

    def _compute(self):
        """
        Compute everything, hopefully resulting in matches!
        """
        # Initialize performance tracker
        perf = _get_perf_tracker()

        # Phase 1: first order matches (matches depending only on the attr tuples)
        perf.start_phase("Phase 1: Coarse matching")
        l.info("Phase 1: Coarse statistical matching")
        phase1_work = 0
        for lib, lib_lmds in self.lmdb.lib_lmds.items():
            self._compute_first_order_matches(lib, lib_lmds)
            for lmd in lib_lmds:
                phase1_work += len(lmd.viable_functions)
        phase1_matches = sum(
            len(matches)
            for lib_matches in self._first_order_matches.values()
            for lmd_matches in lib_matches.values()
            for matches in lmd_matches.values()
        )
        perf.end_phase("Phase 1: Coarse matching", work_items=phase1_work, matches=phase1_matches)

        # Phase 2: Use parallel or sequential version based on jobs setting
        perf.start_phase("Phase 2: FunctionDiff")
        if self._jobs > 1:
            l.info(f"Phase 2: FunctionDiff (PARALLEL with {self._jobs} workers, -j{self._jobs})")
            for lib in self.lmdb.lib_lmds:
                self._compute_second_order_matches_parallel(lib)
        else:
            l.info("Phase 2: FunctionDiff (SEQUENTIAL, -j1)")
            for lib in self.lmdb.lib_lmds:
                self._compute_second_order_matches(lib)

        phase2_matches = sum(
            len(matches)
            for lib_matches in self._second_order_matches.values()
            for lmd_matches in lib_matches.values()
            for matches in lmd_matches.values()
        )
        perf.end_phase("Phase 2: FunctionDiff", matches=phase2_matches)

        # Phase 3: Callee context
        perf.start_phase("Phase 3: Callee context")
        l.info("Phase 3: Callee context")
        self._compute_third_order()
        perf.end_phase("Phase 3: Callee context")

        # Phase 4: Caller context
        perf.start_phase("Phase 4: Caller context")
        l.info("Phase 4: Caller context")
        self._compute_fourth_order()
        perf.end_phase("Phase 4: Caller context")

        # Phase 5: Cleanup
        perf.start_phase("Phase 5: Deduplication")
        l.info("Phase 5: Cleanup")
        self._dedup()
        perf.end_phase("Phase 5: Deduplication")

        # Log performance summary
        perf.log_summary()
