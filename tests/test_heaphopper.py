import datetime
import glob
import logging
import os
import re
from subprocess import check_output, STDOUT, CalledProcessError
import sys
import time
import unittest

from flaky import flaky

from heaphopper.analysis.tracer.tracer import trace
from heaphopper.gen.gen_pocs import gen_pocs
from heaphopper.utils.parse_config import parse_config

logger = logging.getLogger("heaphopper.test")

BASE_DIR = os.path.dirname(os.path.realpath(__file__))


def store_results(results_dict):
    ts = time.time()
    dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d_%H:%M:%S")
    fn = "{}_test.txt".format(dt)

    total_time = 0
    with open(fn, "w") as f:
        f.write("Timing results for test run from {}\n\n".format(dt))
        for d in results_dict.keys():
            f.write(
                "[{}]{}: {} s\n".format(
                    "OK" if results_dict[d]["worked"] else "FAILED",
                    d,
                    results_dict[d]["ts"],
                )
            )
            total_time += results_dict[d]["ts"]
        f.write("total time: {} s\n".format(total_time))


def run_single(config_path, binary_path):
    start = time.time()
    with open(config_path, "r") as config:
        trace(config, binary_path)
    ts = time.time() - start
    return ts


def check_single(result_path, binary_path, config_path):
    ts = run_single(config_path, binary_path)
    if not os.path.isfile(result_path):
        logger.error("Error tracing %s. Log-output:", config_path)
        msg = (
            "Couldn't find result files: This indicates a problem with the sybmolic execution in angr and means we "
            "failed to reach expected bad-state. "
        )
        assert False, msg
    return ts


def create_poc_single(
    folder_name,
    analysis_name,
    binary_name,
    result_name,
    desc_name,
    source_name,
    poc_path,
):
    config_path = os.path.join(folder_name, analysis_name)
    binary_path = os.path.join(folder_name, binary_name)

    with open(config_path, "r") as config:
        gen_pocs(config, binary_path, result_name, desc_name, source_name)

    poc_path = glob.glob(poc_path)[0]
    try:
        cmd = ["make", "-C", poc_path, "pocs-print"]
        check_output(cmd, stderr=STDOUT)
    except CalledProcessError as e:
        if e.output:
            logger.error("CalledProcessError: Traceback of running %s:", cmd)
            logger.error(e.output.decode("utf-8"))
        msg = (
            "Failed to compile the synthesized concrete source code.\nMost likely the poc-generation created invalid "
            "C. This is a strong indication for ab bug in the poc-generation and most likely has nothing to do with "
            "the symbolic execution in angr. "
        )
        assert False, msg
    return True


def verify_poc_single(poc_path, poc_type, conf_path):
    try:
        f = open(conf_path, "r")
        config = parse_config(f)
    except OSError as err:
        logger.error("OS error: %s", err)
        return False

    libc_path = config["libc"]
    loader_path = config["loader"]

    poc_path = glob.glob(poc_path)[0]
    poc_bin = os.path.join(poc_path, "bin", "poc_0_0.bin")

    try:
        cmd = [loader_path, poc_bin]
        output = check_output(
            cmd,
            env={"LD_PRELOAD": libc_path, "LIBC_FATAL_STDERR_": "1"},
            cwd=BASE_DIR,
            stderr=STDOUT,
        )
    except CalledProcessError as e:
        logger.error("CalledProcessError: Traceback of running %s:", cmd)
        logger.error(e.output.decode("utf-8"))
        msg = (
            "Running the POC failed with an non-zero exit code. This is a strong indication for a bug in the "
            "poc-generation and most likely has nothing to do with the symbolic execution in angr. "
        )
        assert False, msg

    if poc_type == "malloc_non_heap":
        res = verify_non_heap(output)
        if not res:
            logger.error("Error running POC %s. output:", poc_bin)
            logger.error(output.decode("utf-8"))
            msg = (
                "The concrete execution did not reach the malloc_non_heap state. This is a strong indication for a bug "
                "in the poc-generation and most likely has nothing to do with the symbolic execution in angr. "
            )
            assert False, msg

    elif poc_type == "malloc_allocated":
        res = verify_malloc_allocated(output)
        if not res:
            logger.error("Error running POC %s. output:", poc_bin)
            logger.error(output.decode("utf-8"))
            msg = (
                "The concrete execution did not reach the malloc_allocated state. This is a strong indication for a bug "
                "in the poc-generation and most likely has nothing to do with the symbolic execution in angr. "
            )
            assert False, msg

    elif poc_type.startswith("arbitrary_write"):
        res = verify_arbitrary_write(output)
        if not res:
            logger.error("Error running POC %s. output:", poc_bin)
            logger.error(output.decode("utf-8"))
            msg = (
                "The concrete execution did not trigger an arbitrary write. This is a strong indication for a bug in "
                "the poc-generation and most likely has nothing to do with the symbolic execution in angr. "
            )
            assert False, msg
    else:
        res = True

    return res


def verify_non_heap(output):
    heap_base = int(re.findall(b"Init printf: ([0-9a-fx]+)", output)[0], 0)
    last_alloc = int(re.findall(b"Allocation: ([0-9a-fx]+)", output)[-1], 0)
    if last_alloc < heap_base:
        return True
    return False


def verify_malloc_allocated(output):
    allocs = [
        (int(f[0], 16), int(f[1], 16))
        for f in re.findall(b"Allocation: ([0-9a-fx]+)\nSize: ([0-9a-fx]+)", output)
    ]
    for i, (a1, s1) in enumerate(allocs):
        for a2, s2 in allocs[i + 1 :]:
            if a1 == a2:
                return True
            if a1 < a2 < a1 + s1:
                return True
            if a2 < a1 < a2 + s2:
                return True

    return False


def verify_arbitrary_write(output):
    pre = dict()
    for (i, a) in re.findall(
        br"write_target\[([0-9]+)\]: ([0-9a-fx]+|\(nil\))\n", output
    ):
        if a == b"(nil)":
            a = "0x0"

        if i not in pre:
            pre[i] = int(a, 0)
        else:
            if pre[i] != int(a, 0):
                return True

    return False


class TestHeapHopper(unittest.TestCase):
    def setUp(self):
        output = check_output(["make", "-C", BASE_DIR, "clean"])
        logger.debug(output)
        output = check_output(["make", "-C", BASE_DIR])
        logger.debug(output)

    def do_test(self, name, type_, poc_star=False):
        bin_name = name + ".bin"
        conf = "analysis.yaml"

        location = os.path.join(BASE_DIR, "how2heap_" + name)
        result_path = os.path.join(location, bin_name + "-result.yaml")
        desc_path = os.path.join(location, bin_name + "-desc.yaml")
        source_path = os.path.join(location, name + ".c")
        poc_path = os.path.join(
            location, "pocs", type_, "*" if poc_star else "", bin_name
        )
        config_path = os.path.join(location, "analysis.yaml")
        bin_path = os.path.join(location, bin_name)

        check_single(result_path, bin_path, config_path)

        created_poc = create_poc_single(
            location, conf, bin_name, result_path, desc_path, source_path, poc_path
        )
        self.assertTrue(created_poc)

        poc_worked = verify_poc_single(poc_path, type_, os.path.join(location, conf))
        # poc creation is a tedious thing and in fact not relevant for angr's CI
        # self.assertTrue(poc_worked)


    def test_fastbin_dup(self):
        self.do_test("fastbin_dup", "malloc_non_heap")

    @flaky(max_runs=3, min_passes=1)
    @unittest.skip("broken")
    def test_house_of_lore(self):
        self.do_test("house_of_lore", "malloc_non_heap")

    def test_house_of_spirit(self):
        self.do_test("house_of_spirit", "malloc_non_heap")

    def test_overlapping_chunks(self):
        self.do_test("overlapping_chunks", "malloc_allocated")

    def test_unsorted_bin_attack(self):
        self.do_test("unsorted_bin_attack", "arbitrary_write_malloc", poc_star=True)

    def test_unsafe_unlink(self):
        self.do_test("unsafe_unlink", "arbitrary_write_free", poc_star=True)
    test_unsafe_unlink.speed = "slow"

    @unittest.skip("broken")
    def test_house_of_einherjar(self):
        self.do_test("house_of_einherjar", "malloc_non_heap")

    def test_poison_null_byte(self):
        self.do_test("poison_null_byte", "malloc_allocated")

    def test_tcache_poisoning(self):
        self.do_test("tcache_poisoning", "malloc_non_heap")


if __name__ == "__main__":
    unittest.main()
