# Contributing

Issues and pull requests are welcome.

## Reporting a wrong decode or wrong semantics

Use the
[wrong decode / semantics](https://github.com/geepot/ghidra-c6000/issues/new?template=wrong-decode.md)
issue template. The most useful report has:

- the Ghidra version, extension version and language id (`C6000:LE:32:default`, ...);
- the address and the raw bytes of the whole 32-byte fetch packet (for compact
  code the header word decides how the other words decode);
- what Ghidra shows (listing text, or the p-code / decompiler output) and what
  you expected, with the SPRUFE8B figure, table or section that says so;
- if you have it, the same bytes through GNU `objdump -m tic6x`
  (`objdump -D -b binary -m tic6x --endian=little --adjust-vma=<base> packet.bin`;
  the input must be at least 32 bytes).

Only post bytes you are allowed to share. A single fetch packet is usually enough; never
attach whole firmware images.

## Changing the module

- Cite the SPRUFE8B (or SPRU732J) figure, table or section behind every
  encoding or semantic change, in the code comment and the commit message.
  Never copy code from another disassembler (see [`NOTICE.md`](NOTICE.md));
  binutils and Capstone are oracles only.
- Edit the generators (`tools/gen_*.py`, `tools/build_encodings.py`), not the
  generated `.sinc` files, which say so in their first line.
- Add a fixture under `tests/fixtures/` and a `ghidra_scripts/C6000*Test.java`
  check for new semantics, covering both endian modes.
- Run `python3 tools/verify.py --jobs 2` before opening a PR, and say in the PR
  which checks you ran. Use `--with-ti` when changing predicate proofs,
  caller continuations or post-loop dispatch; it requires TI's assembler.
  The runner builds and tests both endian modes in a scratch Ghidra copy.
  [docs/verification.md](docs/verification.md) explains focused reruns, retained
  evidence, external-image checks and GNU-oracle comparisons. Add new release
  dependencies to the runner's fixture registry.
- Add a line to [`CHANGELOG.md`](CHANGELOG.md) under *Unreleased*.
- Do not commit firmware, TI manuals or text extracted from them.

The source layout is described in
[docs/internals.md](docs/internals.md#repository-layout). Release preparation and
compatibility metadata are described in [docs/release.md](docs/release.md).

## Script compatibility and troubleshooting

Keep verification scripts compatible with every CI Ghidra version. In particular, use
the four-argument `PcodeExecutor(language, arithmetic, state, reason)` constructor; the
two-argument convenience constructor requires 12.2. Construct a `PcodeProgram` with the
library's symbols and pass it to `begin`; the `begin(List, symbols)` symbol-map
parameter changed between 12.1 and 12.2.

Ghidra compiles a script directory as one OSGi bundle. A compile error in one Java file
can therefore prevent sibling scripts from loading. In Ghidra 12.1.3, this can appear as
`Failed to get OSGi bundle containing script` when a compiler diagnostic triggers a
`GhidraSourceBundle.tryBuild` null-source failure. Check sibling compile errors before
debugging the script loader. Keep independently buildable scripts in separate
`-scriptPath` directories.
