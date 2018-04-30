import nose
from povsim import CGCPovSimulator

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
pov_location = str(os.path.dirname(os.path.realpath(__file__)))

import logging

def test_good_pov():
    '''
    Test a POV which exploits the target binary.
    '''

    pov_tester = CGCPovSimulator()
    pov_path = os.path.join(pov_location, 'good.pov')
    binary_path = os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01")
    result = pov_tester.test_binary_pov(pov_path, binary_path, enable_randomness=True)

    nose.tools.assert_true(result)

def test_bad_pov():
    '''
    Test a POV which fails to exploit the target binary.
    '''

    pov_tester = CGCPovSimulator()
    pov_path = os.path.join(pov_location, 'bad.pov')
    binary_path = os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01")
    result = pov_tester.test_binary_pov(pov_path, binary_path, enable_randomness=True)

    nose.tools.assert_false(result)

def test_multitesting():
    '''
    Test POV multitesting
    '''

    pov_tester = CGCPovSimulator()
    pov_path = os.path.join(pov_location, 'good.pov')
    binary_path = os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01")

    result = pov_tester.test_binary_pov(pov_path, binary_path, enable_randomness=True, times=10)

    nose.tools.assert_true(all(result))

    pov_tester = CGCPovSimulator()
    pov_path = os.path.join(pov_location, 'bad.pov')
    binary_path = os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01")

    result = pov_tester.test_binary_pov(pov_path, binary_path, enable_randomness=True, times=10)

    nose.tools.assert_false(any(result))

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("povsim").setLevel("DEBUG")
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
