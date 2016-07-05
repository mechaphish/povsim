### povsim

Test generated Povs.

```python
>>> from povsim import CGCPovSimulator
>>> import logging
>>> logging.getLogger('povsim').setLevel("INFO")
>>> pov_tester = CGCPovSimulator()
>>> pov_tester.test_binary_pov('example.pov', 'example.challenge', enable_randomness=True)
INFO    | 2016-07-04 20:40:55,553 | povsim.cgc_pov_simulator | recieved pov_type of 1
INFO    | 2016-07-04 20:40:55,553 | povsim.cgc_pov_simulator | entering type1 negotiation
INFO    | 2016-07-04 20:40:55,553 | povsim.cgc_pov_simulator | recieved a ipmask of 0x7f7f7f7f
INFO    | 2016-07-04 20:40:55,553 | povsim.cgc_pov_simulator | recieved a regmask of 0x7f7f7f7f
INFO    | 2016-07-04 20:40:55,553 | povsim.cgc_pov_simulator | recieved a regnum of 0x3
INFO    | 2016-07-04 20:40:55,553 | povsim.cgc_pov_simulator | requesting a register value of 0xddafe8af
INFO    | 2016-07-04 20:40:55,553 | povsim.cgc_pov_simulator | requesting a ip value of 0x86992bcb
INFO    | 2016-07-04 20:40:55,627 | povsim.cgc_pov_simulator | register value set to: 0x5d2f682f
INFO    | 2016-07-04 20:40:55,627 | povsim.cgc_pov_simulator | ip value set to: 0x6192b4b
INFO    | 2016-07-04 20:40:55,627 | povsim.cgc_pov_simulator | pov successful? True
True # True signals the pov successfully exploited the challenge binary
```
