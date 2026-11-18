# RCE matrix - one folder per run, one cell per family

Generated from each run's `cells.json` by `build.py`; the cells are the ones `poc/row.py`
actually drives. Status is the harness verdict when a verification log is present, otherwise
the cell is reported as `positive` because a PoC exists for it.

| run | request_line_split | body_replay_desync | cache_exec_poison | 1xx_nesting | pct2f_split | config_quoted_space | multi_hop_chain | retry_double_exec | total positive |
|---|---|---|---|---|---|---|---|---|---|
| level-5-a4ba853a82fe | positive | negative | positive | negative | negative | negative | negative | negative | 2 |
| stage-05__cpp__20261116T022712Z__1cfd33433d25__e1a28e35 | positive | negative | positive | positive | negative | negative | negative | negative | 3 |
| stage-05__cpp__20261116T022714Z__1cfd33433d25__6baf167b | positive | negative | positive | positive | negative | negative | positive | negative | 4 |
| stage-05__cpp__20261116T022716Z__1cfd33433d25__afdc173f | positive | negative | positive | negative | negative | negative | negative | positive | 3 |
| stage-05__cpp__20261116T025712Z__3aeb255d3d7f__ae021893 | positive | positive | positive | positive | negative | negative | negative | negative | 4 |
| stage-05__cpp__20261116T025714Z__3aeb255d3d7f__f2b3415b | positive | positive | negative* | negative | negative | negative | negative | positive | 3 |
| stage-10__cpp__20261116T022713Z__1cfd33433d25__61cc738c | positive | positive | negative | negative | negative | negative | negative | negative | 2 |
| stage-10__cpp__20261116T022715Z__1cfd33433d25__44bf7f35 | positive | positive | negative | negative | positive | negative | negative | negative | 3 |
| stage-10__cpp__20261116T022716Z__1cfd33433d25__063b0d5e | positive | positive | negative | negative | negative | positive | negative | negative | 3 |
| stage-10__cpp__20261116T025713Z__3aeb255d3d7f__8d5ff1f2 | positive | positive | negative | positive | positive | positive | positive | negative | 6 |
| stage-10__cpp__20261116T025715Z__3aeb255d3d7f__29d05850 | positive | positive | negative | negative | negative | positive | negative | negative | 3 |
| stage-10__cpp__20261116T025716Z__3aeb255d3d7f__6fb186ed | positive | positive | negative | negative | positive | positive | negative | negative | 4 |
| terra-stage10-cpp-20261115-2usd-recovery | positive | positive | negative | negative | positive | negative | negative | negative | 3 |

**Column totals (positive)**
- request_line_split: 13
- body_replay_desync: 9
- cache_exec_poison: 5
- 1xx_nesting: 4
- pct2f_split: 4
- config_quoted_space: 4
- multi_hop_chain: 2
- retry_double_exec: 2

Rows: 13. Cells: 104 (43 verified positive, 0 unverified, 61 negative).

A cell is positive when the harness drives real request bytes at the build and the control
peer sees the effect upstream: an executed request line, a replay the peer accepted as its
own request, an inner response after a 1xx, or a victim served from cache with no fetch.
"A request was sent" is never enough. Severity of the underlying finding is not a criterion,
so the medium retry double-exec counts because a command that already ran runs again.

`*` `f2b3415b` has a cacheable source line but never served the victim from cache in this
harness, so its cache cell stays negative and is not counted.
