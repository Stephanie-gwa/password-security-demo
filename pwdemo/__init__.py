"""
pwdemo — an educational demonstration of why unsalted, fast password
hashes are crackable, and why salted, slow hashing (an established KDF)
resists the same attacks.

Scope, on purpose:
  - Every password used anywhere in this project is synthetic — invented
    for this demo, never sourced from a real breach dataset.
  - Every search (dictionary, brute-force, rainbow chains) is bounded to
    a small keyspace so the whole demonstration runs in seconds.
  - The CLI and example scripts only ever operate on the synthetic
    passwords bundled in synthetic_data.py. There is no interface here
    for testing an arbitrary, real password or hash — this project is a
    teaching tool, not a cracking tool.
"""
__version__ = "1.0.0"
