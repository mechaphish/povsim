import os
import sys
import shutil
import random
import select
import struct
import socket
import signal
import resource
import tempfile
import subprocess
import shellphish_qemu
from multiprocessing import Pool, TimeoutError
from threading import Timer

import angr

import logging

l = logging.getLogger("povsim.cgc_pov_simulator")


class CGCPovSimulator(object):
    registers = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

    def __init__(self, expected_type=None, expected_register=None, qemu=None):
        self.expected_type = expected_type
        self.expected_register = expected_register
        self.forced_qemu = qemu

    @staticmethod
    def _recv_timeout(sock, num_bytes, timeout=15):
        r = b""
        while len(r) < num_bytes:
            rfd, _, _ = select.select([sock], [], [sock], timeout)
            if sock in rfd:
                n = sock.recv(num_bytes-len(r))
                if len(n) == 0:
                    return r
                r += n
            else:
                return r
        return r

    @staticmethod
    def _wait_pid_timeout(pid, options, timeout):
        def kill_proc(p):
            os.kill(p, signal.SIGKILL)

        timer = Timer(timeout, kill_proc, [pid])
        try:
            timer.start()
            return os.waitpid(pid, options)
        except OSError:
            return 0, 0
        finally:
            timer.cancel()

    @staticmethod
    def _reap_pid(pid):
        def kill_proc(p):
            os.kill(p, signal.SIGTERM)

        res = os.waitpid(pid, os.WNOHANG)
        if res == (0, 0):
            l.debug("process %d did not terminate on its own, reaping", pid)
            kill_proc(pid)

    def test_binary_pov(self, pov_path, cb_path, enable_randomness=True, debug=False, bitflip=False, timeout=15, times=1):
        """
        Test a binary POV

        :param pov_path: path to the POV to test
        :param cb_path: path to the challenge binary
        :param enable_randomness: test the binary with random seed
        :param debug: enable debug output from the challenge binary
        :param timeout: timeout to apply to the simulation
        :param times: number of times to the binary, if more than one this is done in parallel
        """

        if times > 1:
            results = None
            try:

                args = [sys.executable, __file__, pov_path, cb_path,
                        str(int(enable_randomness)),
                        str(int(debug)),
                        str(int(bitflip)),
                        str(timeout),
                        str(times)]

                p = subprocess.Popen(args, stdout=subprocess.PIPE)

                stdout, _ = p.communicate()

                p.wait()

                results = [ ]
                for line in stdout.split(b"\n")[:-1]:
                    if line == b"1" or line == b"0":
                        results.append(bool(int(line)))

                return results

            except OSError as e:
                l.warning("encountered OSError (%s) during multitesting, resorting to loop", e)

                results = [ ]
                for _ in range(times):
                    results.append(self._test_binary_pov(pov_path, cb_path, enable_randomness, debug,
                            bitflip, timeout))

            return results

        else:
            return self._test_binary_pov(pov_path, cb_path, enable_randomness, debug, bitflip, timeout)


    def _multitest_binary_pov(self, pov_path, cb_path, enable_randomness, debug, bitflip, timeout, times):

            pool = Pool(processes=4)

            res = [pool.apply_async(self._test_binary_pov,
                                    (pov_path, cb_path, enable_randomness, debug, bitflip, timeout))
                                    for _ in range(times)]

            results = [ ]
            for r in res:
                try:
                    results.append(r.get(timeout=timeout + 5))
                except TimeoutError:
                    results.append(False)

            return results

    def _test_binary_pov(self, pov_filename, cb_path, enable_randomness=True, debug=False, bitflip=False, timeout=15):
        # Test the binary pov
        # sanity checks
        if not os.path.isfile(pov_filename):
            raise ValueError("pov is does not exist")

        if not os.access(pov_filename, os.X_OK):
            raise ValueError("pov is not executable")

        if not os.path.isfile(cb_path):
            raise ValueError("cb does not exist")

        if not os.access(cb_path, os.X_OK):
            raise ValueError("cb is not executable")

        # create the communication pipes
        pov_r, pov_w = os.pipe()
        challenge_r, challenge_w = os.pipe()
        negotiation_pov, negotiation_infra = socket.socketpair()

        if self.forced_qemu == None:
            qemu_path = shellphish_qemu.qemu_path('cgc-base')
        else:
            qemu_path = self.forced_qemu

        # create directory for core files
        directory = tempfile.mkdtemp(prefix='rex-test-', dir='/tmp')
        cb_path = os.path.realpath(cb_path)
        magic_path = os.path.join(directory, "magic")

        # fork off the challenge binary
        challenge_bin_pid = os.fork()
        if challenge_bin_pid == 0:
            try:
                # set up core dumping, only used by type1 though

                # pylint:disable=no-member
                resource.setrlimit(
                        resource.RLIMIT_CORE,
                        (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
                        )

                devnull = open('/dev/null', 'w')
                # close the other entry
                os.close(pov_w)
                os.close(challenge_r)
                os.dup2(pov_r, 0)  # read from pov as stdin
                os.dup2(challenge_w, 1)  # write to the pov
                if not debug:
                    os.dup2(devnull.fileno(), 2)  # silence segfault message)
                if enable_randomness:
                    random.seed()
                    seed = str(random.randint(0, 100000))
                    argv = [qemu_path, "-C", directory, "-seed", seed, "-magicdump", magic_path, cb_path]
                else:
                    argv = [qemu_path, "-C", directory, "-magicdump", magic_path, cb_path]
                if bitflip:
                    argv = [argv[0]] + ["-bitflip"] + argv[1:]
                # argv = [argv[0]] + ["-d","in_asm","-D","/tmp/log1.txt","-singlestep"] + argv[1:]
                os.execve(qemu_path, argv, os.environ)
            finally:
                l.error("an exception happened in the child code (trying to run the cb)")
                sys.exit(1)

        # fork off the pov binary
        pov_pid = os.fork()
        if pov_pid == 0:
            try:
                # close the other entry
                os.close(pov_r)
                os.close(challenge_w)

                os.dup2(challenge_r, 0)  # read from challenge's stdout
                os.dup2(pov_w, 1)  # write to challenge's stdin

                # file descriptor 3 is the negotiation server
                os.dup2(negotiation_pov.fileno(), 3)

                random.seed()
                seed = str(random.randint(0, 100000))
                argv = [qemu_path, "-seed", seed, pov_filename]
                os.execve(qemu_path, argv, os.environ)
            finally:
                l.error("an exception happened in the child code (trying to run the pov)")
                sys.exit(1)

        # clean up the pipes in the host
        os.close(challenge_r)
        os.close(challenge_w)
        os.close(pov_r)
        os.close(pov_w)

        l.debug("challenge_r: %d", challenge_r)
        l.debug("challenge_w: %d", challenge_w)
        l.debug("pov_r: %d", pov_r)
        l.debug("pov_w: %d", pov_w)
        l.debug("pov_pid: %d", pov_pid)
        l.debug("challenge_bin_pid: %d", challenge_bin_pid)

        # negiotation is specific to type1 / type2
        result = self._do_binary_negotiation(negotiation_infra, directory,
                                             challenge_bin_pid, timeout)

        # try to reap child pov, if it's not dead, kill it
        self._reap_pid(pov_pid)

        # clean up test directory
        shutil.rmtree(directory)

        return result

    def _do_binary_negotiation(self, negotiation_pipe, directory,
                               challenge_binary_pid, timeout):
        """
        Negotiate with a PoV binary
        :param negotiation_pipe: pipe to read negotiation materials from
        :param directory: directory core file will be found
        :param challenge_binary_pid: pid of the challenge binary, we will wait
        for it to exit
        :param timeout: timeout for the binary
        :return: boolean describing whether the binary pov behaved correctly
        """

        pov_type = struct.unpack("<I", negotiation_pipe.recv(4))[0]

        # check pov type before doing the correct negotiation
        if self.expected_type is not None:
            if pov_type != self.expected_type:
                l.error("received incorrect pov type")
                return False

        l.info("received pov_type of %d", pov_type)
        if pov_type == 1:
            l.info("entering type1 negotiation")
            return self._do_binary_negotiation_type_1(negotiation_pipe, directory,
                                                      challenge_binary_pid, timeout)
        elif pov_type == 2:
            l.info("entering type2 negotiation")
            return self._do_binary_negotiation_type_2(negotiation_pipe, directory,
                                                      challenge_binary_pid, timeout)
        else:
            l.error("Invalid pov type: %d", pov_type)
            return False

    def _do_binary_negotiation_type_1(self, negotiation_pipe, directory,
                                      challenge_binary_pid, timeout):
        """
        Negotiate with a Type 1 PoV binary
        :param negotiation_pipe: pipe to read negotiation materials from
        :param directory: directory core file will be found
        :param challenge_binary_pid: pid of the challenge binary, we will wait
        for it to exit
        :return: boolean describing whether the binary pov behaved correctly
        """

        ipmask = struct.unpack("<I", self._recv_timeout(negotiation_pipe, 4))[0]
        regmask = struct.unpack("<I", self._recv_timeout(negotiation_pipe, 4))[0]
        regnum = struct.unpack("<I", self._recv_timeout(negotiation_pipe, 4))[0]

        l.info("received a ipmask of %#x", ipmask)
        l.info("received a regmask of %#x", regmask)
        l.info("received a regnum of %#x", regnum)

        register = CGCPovSimulator.registers[regnum]
        if self.expected_register is not None:
            if register != self.expected_register:
                l.error("unexpected register number received during negotiation")
                return False

        if bin(regmask).count("1") < 20:
            l.error("received a regmask with not enough bits set")
            return False
        if bin(ipmask).count("1") < 20:
            l.error("received a ipmask with not enough bits set")
            return False

        random.seed()
        reg_val = random.randint(0, 0xffffffff)
        ip_val = random.randint(0, 0xffffffff)

        l.info("requesting a register value of %#x", reg_val)
        l.info("requesting a ip value of %#x", ip_val)

        negotiation_pipe.send(
                struct.pack("<I", ip_val) + struct.pack("<I", reg_val)
                )

        l.debug("waiting on challenge binary...")

        _, returncode = self._wait_pid_timeout(challenge_binary_pid, 0, timeout)

        l.debug("... challenge binary terminated")

        # only check the relevant bits
        returncode &= 0x7f

        if returncode not in [signal.SIGSEGV, signal.SIGILL]:
            l.error("challenge binary did not crash, instead returned exit code %d", returncode)
            return False

        corefile = None
        for item in os.listdir(directory):
            if item.endswith('.core'):
                corefile = os.path.join(directory, item)
                break

        if corefile is None:
            l.error("no core file found, challenge binary crashed?")
            return False

        l.debug("found corefile for challenge in file %s", corefile)

        # load core file and grab registers
        p = angr.Project(corefile)
        set_reg_value = None
        set_ip_value = None
        for reg, val in p.loader.main_object.thread_registers().items():
            if reg == register:
                set_reg_value = val
            if reg == "eip":
                set_ip_value = val

        if set_ip_value is None:
            l.error("eip's value not found in core file")
            return False
        if set_reg_value is None:
            l.error("%s's value not found in core file", register)
            return False

        l.info("register value set to: %#x", set_reg_value)
        l.info("ip value set to: %#x", set_ip_value)

        register_set = set_reg_value & regmask == reg_val & regmask
        ip_set = set_ip_value & ipmask == ip_val & ipmask

        if not ip_set:
            l.warning("ip was not set correctly")

        if not register_set:
            l.warning("register was not set correctly")

        # clean up the dropped core
        os.remove(corefile)

        result = register_set and ip_set
        l.info("pov successful? %s", result)
        return result

    @staticmethod
    def _do_binary_negotiation_type_2(negotiation_pipe, directory,
                                      challenge_bin_pid, timeout):
        """
        Negotiate with a Type 2 PoV binary
        :param negotiation_pipe: pipe to read negotiation materials from
        :param directory: directory core file to be found in
        :param challenge_bin_pid: pid of the challenge binary, we will for
        it to exit
        :return: boolean describing whether the binary pov behaved correctly
        """

        # have the exploit leak from the magic page, believe this is fixed
        region_addr = 0x4347c000
        region_size = 0x1000
        read_size = 4

        type2_vals = [region_addr, region_size, read_size]
        type2_vals_elems = map(lambda x: struct.pack("<I", x), type2_vals)
        l.info("sent off type2 params (%#x, %#x, %#x)", region_addr, region_size, read_size)
        negotiation_pipe.send(b''.join(type2_vals_elems))

        # receive the leaked flag data
        flag_data = CGCPovSimulator._recv_timeout(negotiation_pipe, read_size, timeout)

        if len(flag_data) < 4:
            l.info("didnt receive enough bytes")
        else:
            l.info("received flag data %#x", struct.unpack("<I", flag_data)[0])

        # check if it exists within the region
        with open(os.path.join(directory, 'magic'), 'rb') as fp:
            magic_data = fp.read()
        succeeded = flag_data in magic_data and len(flag_data) == read_size

        l.info("pov successful? %s", succeeded)

        # wait for the challenge to exit
        CGCPovSimulator._reap_pid(challenge_bin_pid)

        return succeeded

if __name__ == "__main__":
    cps = CGCPovSimulator()

    _pov_path = sys.argv[1]
    _cb_path = sys.argv[2]
    _enable_randomness = bool(int(sys.argv[3]))
    _bitflip = bool(int(sys.argv[4]))
    _debug = bool(int(sys.argv[5]))
    _timeout = int(sys.argv[6])
    _times = int(sys.argv[7])

    #_results = cps._multitest_binary_pov(_pov_path,
    #        _cb_path, _enable_randomness, _bitflip, _debug, _timeout, _times)

    #for r in _results:
    #    print (str(int(r)))

    for _i in range(_times):
        print (str(int(cps._test_binary_pov(_pov_path,
            _cb_path, _enable_randomness, _bitflip, _debug, _timeout))))
