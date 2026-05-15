# network-sec-virus-scanner

Sentinel is a virus scanner that walks a directory tree, compares each file
against a signature database (MD5, SHA-256, hex byte patterns) and a set of
heuristic regex rules, and writes a log report.

## Demo fixture: `tests/fixtures/demo_tree/`

A small nested directory used for the end-to-end smoke test
(`tests/test_demo_tree_smoke.py`). It exercises every scan engine plus the
directory walker against the default `data/signatures.json` and
`data/heuristic_rules.example.json`.

```
tests/fixtures/demo_tree/
└── top/
    ├── clean1.txt                  # clean — plain text, no signature/rule hits
    ├── sub1/
    │   ├── clean2.bin              # clean — small binary, no hits
    │   └── deep/
    │       └── eicar.com           # infected — full EICAR test string
    │                               # (hash + hex-pattern hits)
    └── sub2/
        ├── with_pattern.bin        # infected — EICAR hex prefix embedded
        │                           # in null padding (pattern-only hit)
        └── suspicious.txt          # suspicious — triggers the
                                    # `shell-eval-marker` heuristic
```

The fixture is deliberately small so it can be committed and replayed
deterministically in CI. `eicar.com` contains the real EICAR test string
(harmless by design but recognised by every mainstream antivirus); some
endpoint security tools may quarantine it on checkout.

### Running the smoke test

```
PYTHONPATH= uv run pytest tests/test_demo_tree_smoke.py
```

Expected outcome: exit code `1` (`EXIT_INFECTED`), report flags
`eicar.com`, `with_pattern.bin`, and `suspicious.txt`, and reports the two
clean files as clean.
