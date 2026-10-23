# Portable RE markup: before/after

Markup transferred from `lua-gcc11-O2` to `lua-gcc15-O2` (710 analyst-named functions, 704 of them with a counterpart in B).

| Method | transfer_recall | transfer_precision | comment_recall | divergence_flagged |
|---|---|---|---|---|
| Baseline: Address-keyed re-apply (OfrakProject script) | 0.001 | 0.019 | 0.001 | no |
| Baseline: Symbol table re-imported by Ghidra's ImportSymbolsScript | 0.001 | 0.003 | 0.000 | no |
| Feature: #1 Anchors derived from A | 0.230 | 0.994 | 0.230 | no |
| Feature: #2 Portable markup import | 0.338 | 1.000 | 0.338 | yes |

#2 with partial markup (100 random subsets of 71 of the analyst's functions): transfer_precision 1.000 at worst (1.000 on average), transfer_recall 0.347 on average; 0 subsets put a name on a wrong function.

Control (same binary, expected to be unchanged):

| Measurement | before | after |
|---|---|---|
| serialize_restore | 1.000 | 1.000 |
| ofrak_project_replay | 1.000 | 1.000 |
| portable_round_trip (feature) | n/a | 1.000 |

Produced from:

- before: OFRAK `1e1ef750222c1a842248ae7bdcae576bfdedae65` (harness `0ead669174b47c6657794b470999e4383da54c25`), Ghidra 11.3.2, committed Ghidra analysis captures
- after: OFRAK `0ead669174b47c6657794b470999e4383da54c25` (harness `0ead669174b47c6657794b470999e4383da54c25`), Ghidra 11.3.2, committed Ghidra analysis captures

Assets (SHA-256):

- `lua-gcc11-O2`: `553c0ffa8637b6586ce9131211da18a4717a5d0d9d56c2e6246a814d23ccb473`
- `lua-gcc11-O2.gzf`: `bc976b5c9285ec2c9f020d062d62ba5c90423c80df53da8e90a34d6a9fe21f0f`
- `lua-gcc11-O2.unstripped`: `4d8b099aa9c3c50af3d215c2bf96ed0d90543f188de5afa894f6557e6340b2e4`
- `lua-gcc15-O2`: `582b361265586e7df5ef85ce118b6e8ddac99babeb697929331a2b698d521ce2`
- `lua-gcc15-O2.gzf`: `03748ba14436bc236f768b645d8f89af9b44509a7903452eb4e7f9ec4e3a1c0a`
- `lua-gcc15-O2.unstripped`: `ecd5b4445466ca3aab90bf14c245a2543947085f8e24384b8c586269865394f3`
