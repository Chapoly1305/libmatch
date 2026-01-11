import networkx
import logging
import pickle
import os
import time
import tempfile
import shutil
import subprocess
import angr
import gc
from multiprocessing import Pool
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
from collections import defaultdict
from .lmd import LibMatchDescriptor
from .utils import PROJECT_KWARGS
from .libmatch import LibMatch
from .utils import score_matches

l = logging.getLogger("bdsig.lmdb")


def _build_lmd_worker(filepath):
    """
    Worker function to build a single LMD from a file.
    Each worker creates its own angr.Project and LMD.

    :param filepath: Path to the .o/.obj file
    :returns: Tuple of (filepath, LMD) if successful, (filepath, None) if failed
    """
    try:
        lmd = LibMatchDescriptor.make_signature(filepath, **PROJECT_KWARGS)
        lmd.release_cfg()  # Release CFG before returning - saves memory and pickle size
        gc.collect()
        return (filepath, lmd)
    except angr.errors.AngrCFGError:
        l.warning(f"No executable data for {filepath}, skipping")
        return (filepath, None)
    except Exception as e:
        l.exception(f"Could not make signature for {filepath}")
        return (filepath, None)


def _log_perf(label, start_time=None, extra=""):
    """Log performance info for LMDB operations."""
    if HAS_PSUTIL:
        try:
            # USS = Unique Set Size: memory private to this process (most accurate)
            mem_gb = psutil.Process().memory_full_info().uss / (1024 * 1024 * 1024)
        except (AttributeError, psutil.AccessDenied):
            # Fallback to RSS if USS unavailable
            mem_gb = psutil.Process().memory_info().rss / (1024 * 1024 * 1024)
        if start_time:
            elapsed = time.time() - start_time
            l.info(f"[LMDB-PERF] {label}: {elapsed:.2f}s | Mem: {mem_gb:.2f} GB {extra}")
        else:
            l.info(f"[LMDB-PERF] {label} | Mem: {mem_gb:.2f} GB {extra}")

class LibMatchDatabase(object):
    """
    A container for a lot of LibMatchDescriptors and their metadata.

    An LMDB is based on a set of libraries in a directory structure, similar to how they are found on the filesystem.
    The top level should contain folders for each arch-tuple (e.g., arm-none-eabi-)
    THe next level should consist of one folder per library.
    Under that, they can contain any arbitrary folder structure (e.g., you can just pile a bunch of library folders in there and it'll get figured out)
    """
    def __init__(self, lib_lmds):
        self.lib_lmds = lib_lmds
        self._build_sym_list(lib_lmds)
        self.symbols = defaultdict(list) # Mapping of string names to all the libraries and objects that contain them.
                                                      # Used primarily for scoring

    def _smoosh(self, candidates):
        for f_addr, stuff in candidates.items():
            if len(stuff) <= 1:
                continue

            name = stuff[0][2].function_b.name
            for lib, lmd, fd in stuff:
                if name != fd.function_b.name:
                    break
            else:
                # Smoosh it!
                candidates[f_addr] = [stuff[0]]
        return candidates

    def _postprocess_matches(self, target_lmd, results):
        """
        Clean up the matches for the user.
        This encodes the behavior "we consider it a match if we 
        match with exactly one name"
        """
        final_matches = {}
        collisions = 0
        junk = 0
        guesses = 0
        for f_addr, match_infos in results.items():
            if len(match_infos) > 1:
                collisions += 1    
                continue
            if f_addr not in target_lmd.viable_functions:
                # we put a name on it, but it's a stub!
                # What. Ever.
                junk += 1
                continue
            for lib, lmd, match in match_infos:
                if isinstance(match, str):
                    sym_name = match
                    guesses += 1
                else:
                    obj_func_addr = match.function_b.addr
                    sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
                final_matches[f_addr] = sym_name
        l.warning("Detected %d collisions" % collisions)
        l.warning("Ignored %d junk function matches" % junk)
        l.warning("Made %d guesses", guesses)
        l.warning("Matched %d symbols" % len(list(final_matches.keys())))
        return final_matches

    def match(self, lmd_path, score=False, jobs=None):
        """
        Scan the database and try to match all libraries with the target.

        :param lib: Either a string (program path) or a LibMatchDescriptor
        :param score: Enable scoring mode
        :param jobs: Number of parallel workers (None for auto-detect, 1 for sequential)
        :return: A dictionary of addresses in the program to possible symbols.
        """
        match_start = time.time()
        _log_perf("Match started")

        if isinstance(lmd_path, LibMatchDescriptor):
            lmd = lmd_path
        else:
            load_start = time.time()
            lmd = LibMatchDescriptor.load_path(lmd_path)
            _log_perf("LMD loaded", load_start)

        candidates = []
        try:
            libmatch_start = time.time()
            self.lm = LibMatch(lmd, self, jobs=jobs)
            _log_perf("LibMatch computation", libmatch_start)
            candidates = self.lm._candidate_matches
            plain_candidates = self.lm._plain_matches
        except Exception as e:
            l.exception("Error computing matches")
            raise
        # TODO: This is where we put multi-library heuristics!

        postprocess_start = time.time()
        candidates = self._smoosh(candidates)
        plain_candidates = self._smoosh(plain_candidates)
        if score:
            l.info("############### UNREFINED MATCHES ###############")
            score_matches(lmd_path, plain_candidates, self)
            l.info("############### FINAL MATCHES ###############")
            score_matches(lmd_path, candidates, self)

        out = self._postprocess_matches(lmd, candidates)
        _log_perf("Post-processing", postprocess_start, f"| Final matches: {len(out):,}")
        _log_perf("Match complete", match_start, f"| Total symbols matched: {len(out):,}")
        return out

    # Creation and Serialization
    @staticmethod
    def _extract_archive(archive_path, extract_dir):
        """
        Extract object files from a .a archive file.

        :param archive_path: Path to the .a archive file
        :param extract_dir: Directory to extract files into
        :return: List of extracted .o file paths
        """
        extracted_files = []
        archive_name = os.path.basename(archive_path)

        # Convert to absolute path for use with cwd in subprocess
        archive_path_abs = os.path.abspath(archive_path)

        # Create a subdirectory for this archive to avoid name collisions
        archive_extract_dir = os.path.join(extract_dir, archive_name.replace('.a', ''))
        os.makedirs(archive_extract_dir, exist_ok=True)

        try:
            # Use 'ar' to list contents first
            result = subprocess.run(
                ['ar', '-t', archive_path_abs],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                l.warning(f"Failed to list archive {archive_path}: {result.stderr}")
                return []

            # Extract all files (larger timeout for big archives like libCHIP.a)
            result = subprocess.run(
                ['ar', '-x', archive_path_abs],
                capture_output=True,
                text=True,
                cwd=archive_extract_dir,
                timeout=300
            )

            if result.returncode != 0:
                l.warning(f"Failed to extract archive {archive_path}: {result.stderr}")
                return []

            # Find all extracted .o files
            for fname in os.listdir(archive_extract_dir):
                if fname.endswith('.o') or fname.endswith('.obj'):
                    extracted_files.append(os.path.join(archive_extract_dir, fname))

            l.info(f"Extracted {len(extracted_files)} object files from {archive_name}")

        except subprocess.TimeoutExpired:
            l.warning(f"Timeout extracting archive {archive_path}")
        except FileNotFoundError:
            l.error("'ar' command not found. Please install binutils.")
        except Exception as e:
            l.exception(f"Error extracting archive {archive_path}: {e}")

        return extracted_files

    @staticmethod
    def _process_object_file(fullfname, lmds):
        """
        Process a single object file and add its signature to lmds set.

        :param fullfname: Full path to the object file
        :param lmds: Set to add the LMD to
        :return: True if successful, False otherwise
        """
        try:
            lmd = LibMatchDescriptor.make_signature(fullfname, **PROJECT_KWARGS)
            lmd.release_cfg()  # Release CFG immediately - saves 5-7GB per file
            lmds.add(lmd)
            gc.collect()  # Force garbage collection before next file
            _log_perf(f"Processed {os.path.basename(fullfname)}")
            return True
        except angr.errors.AngrCFGError:
            l.warning("No executable data for %s, skipping" % fullfname)
        except Exception as e:
            l.exception("Could not make signature for " + fullfname)
        return False

    @staticmethod
    def _build_lib(lib_dir, jobs=1):
        """
        Build signatures for all object files in a library directory.
        Supports both .o/.obj files directly and .a archive files.
        Uses parallel processing with imap_unordered for continuous work distribution.

        :param lib_dir: Directory containing library files
        :param jobs: Number of parallel workers (-j). Default 1 (sequential).
        :return: Set of LibMatchDescriptor objects
        """
        lmds = set()
        temp_dirs = []  # Track temp directories for cleanup
        files_to_process = []  # Collect all files first

        try:
            # Phase 1: Collect all files to process (extract archives in main process)
            for dirName, subdirList, fileList in os.walk(lib_dir):
                l.info('Found directory: %s' % dirName)
                for fname in fileList:
                    fullfname = os.path.join(dirName, fname)

                    # Handle .o and .obj files directly
                    if fname.endswith(".o") or fname.endswith(".obj"):
                        files_to_process.append(fullfname)

                    # Handle .a archive files - extract in main process
                    elif fname.endswith(".a"):
                        l.info(f"Extracting archive: {fullfname}")
                        temp_dir = tempfile.mkdtemp(prefix="libmatch_ar_")
                        temp_dirs.append(temp_dir)
                        extracted_files = LibMatchDatabase._extract_archive(fullfname, temp_dir)
                        files_to_process.extend(extracted_files)

            total_files = len(files_to_process)
            l.info(f"Collected {total_files} object files to process")

            if total_files == 0:
                return lmds

            # Phase 2: Process files (parallel or sequential)
            if jobs > 1 and total_files > 1:
                l.info(f"Building LMDs in parallel with {jobs} workers (-j{jobs})")
                start_time = time.time()
                processed = 0
                successful = 0

                with Pool(processes=jobs) as pool:
                    # imap_unordered returns results as soon as workers finish
                    # No waiting for batches - continuous work distribution
                    for filepath, lmd in pool.imap_unordered(_build_lmd_worker, files_to_process):
                        processed += 1
                        if lmd is not None:
                            lmds.add(lmd)
                            successful += 1

                        # Progress logging every 10% or every 50 files
                        if processed % max(1, total_files // 10) == 0 or processed % 50 == 0:
                            elapsed = time.time() - start_time
                            rate = processed / elapsed if elapsed > 0 else 0
                            _log_perf(f"Progress: {processed}/{total_files} ({100*processed//total_files}%)",
                                     extra=f"| {successful} successful | {rate:.1f} files/sec")

                elapsed = time.time() - start_time
                l.info(f"Parallel build complete: {successful}/{total_files} successful in {elapsed:.1f}s")
            else:
                # Sequential mode (default, -j1)
                l.info("Building LMDs sequentially (-j1)")
                for fullfname in files_to_process:
                    l.info(f"Making signature for {os.path.basename(fullfname)}")
                    LibMatchDatabase._process_object_file(fullfname, lmds)

        finally:
            # Clean up temp directories after all processing is done
            for temp_dir in temp_dirs:
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    l.warning(f"Failed to clean up temp directory {temp_dir}: {e}")

        return lmds

    @staticmethod
    def build(root_dir, output_path=None, jobs=1):
        """
        Constructor to build the database, from a directory tree

        :param root_dir: Directory containing library subdirectories
        :param output_path: Optional output path for the LMDB file. If None, saves to {parent_dir}/{root_dir_name}.lmdb
        :param jobs: Number of parallel workers (-j). Default 1 (sequential).
        :return: the LMDB
        """
        lmds = dict() # mapping of the lib's name, to the list of lmds it contains
        if not os.path.isdir(root_dir):
            raise ValueError("Must provide a directory to build a database!")

        l.info(f"Building database with -j{jobs}")

        # Divide each folder within the directory into libraries
        for thing in os.listdir(root_dir):
            fullname = os.path.join(root_dir, thing)
            if os.path.isdir(fullname):
                l.info("Building signatures for library %s (%s)" % (thing, fullname))
                lmds[thing] = LibMatchDatabase._build_lib(fullname, jobs=jobs)

        l.info("Making LMDB")
        lmdb = LibMatchDatabase(lmds)
        if output_path is None:
            directory = os.path.dirname(os.path.abspath(root_dir))
            filename = os.path.basename(os.path.abspath(root_dir)) + ".lmdb"
            output_path = os.path.join(directory, filename)
        lmdb.dump_path(output_path)
        l.info("Done")

    def _build_sym_list(self, lmds):
        """
        Build the total list of symbols this database contains.
        If its not in this list, we are for sure not going to match well with it
        (used for scoring)
        :param lmds:
        :return:
        """
        syms = set()
        for _, lmd_list in lmds.items():
            for lmd in lmd_list:
                names = {x.name for x in lmd.viable_symbols}
                syms.update(names)
        self.symbol_names = syms

    def release_all_cfgs(self):
        """
        Release CFG memory from all library LMDs in this database.
        Call this after loading to reduce memory usage.
        Saves ~5-7GB per LMD.
        """
        released = 0
        for lib_name, lmd_list in self.lib_lmds.items():
            for lmd in lmd_list:
                if hasattr(lmd, 'release_cfg'):
                    lmd.release_cfg()
                    released += 1
        l.info(f"Released CFG memory from {released} library LMDs")

    @staticmethod
    def load_path(p):
        with open(p, "rb") as f:
            return LibMatchDatabase.load(f)

    @staticmethod
    def load(f):
        lmdb = pickle.load(f)

        if not isinstance(lmdb, LibMatchDatabase):
            raise ValueError("That's not a InterObjectCallgraph!")
        return lmdb

    @staticmethod
    def loads(data):
        lmdb = pickle.loads(data)

        if not isinstance(lmdb, LibMatchDatabase):
            raise ValueError("That's not a LibMatchDatabase!")
        return lmdb

    def dump_path(self, p):
        l.info(f"Dumping LMDB to {p}...")
        try:
            with open(p, "wb") as f:
                self.dump(f)
                f.flush()
                os.fsync(f.fileno())  # Force OS to write to disk

            # Verify the file is a complete pickle (ends with STOP opcode)
            with open(p, "rb") as f:
                f.seek(-1, 2)  # Seek to last byte
                last_byte = f.read(1)
                if last_byte != b'.':
                    raise RuntimeError(f"Pickle file incomplete: last byte is {last_byte!r}, expected b'.'")

            file_size = os.path.getsize(p)
            l.info(f"Successfully dumped LMDB to {p} ({file_size / (1024**3):.2f} GB)")
        except Exception as e:
            l.error(f"Failed to dump LMDB: {e}")
            raise

    def dump(self, f):
        return pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)

    def dumps(self):
        return pickle.dumps(self, pickle.HIGHEST_PROTOCOL)
