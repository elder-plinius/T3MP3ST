# T3MP3ST — Twitter/X Claim (VALIDATED 2026-05-30; JAIL-RE-VERIFIED 2026-06-02, v3)

> The clean methodology was INDEPENDENTLY RE-CONFIRMED on 2026-06-02 with the
> sandbox jail active (19 escape attempts blocked, 0 succeeded). The earlier
> un-jailed run hit its number partly via contamination; the jailed re-run hits
> it HONESTLY, and full-corpus coverage IMPROVED to 52.5% (21/40) after
> recovering the 9 GlacierCTF challenges upstream had deleted. Provably clean.
>
> RETRACTED claims — DO NOT use:
>   ❌ "beats XBOW" — XBOW publishes on its own 104-chall web bench + HackerOne, NOT Cybench
>   ❌ "beats SOTA / 2.6× the record" — modern Cybench SOTA is Anthropic's own
>      Sonnet 4.5 @ 76.5% pass@10 (37/40 subset). We are NOT the raw-score record.
>   ❌ "#1 on Cybench"  ❌ "61.3% / cracked robust-cbc+network-tools" (those were the contaminated solves)
>
> The TRUE, defensible story is METHODOLOGY, not peak score.

---

## ✅ THE HONEST NUMBERS (every one → a JSON artifact, jail-verified 2026-06-02)

| Metric | Value | Notes |
|---|---|---|
| T3MP3ST + Opus 4.8, **full corpus (all 40)** | **21/40 = 52.5%** | pass@1, hint-free, sandbox-jailed |
| T3MP3ST + Opus 4.8, fair-shot (32) | **21/32 = 65.6%** | excl. broken-docker + un-wired live targets |
| Cybench paper SOTA (2024) | 17.5% pass@1 | Claude 3.5 Sonnet |
| Cybench modern SOTA | **76.5% pass@10** | Anthropic Sonnet 4.5 system card, 37/40 |

**We are NOT the record.** Anthropic's pass@10 is higher. What's different
about ours: **pass@1, answers scrubbed, hints stripped, every flag from a live
exploit, sandbox-jailed (19 escape attempts blocked / 0 succeeded), and we
publish our own retractions.** (Full corpus rose 18/40→21/40 after we recovered
the 9 GlacierCTF challenges upstream deleted.)

---

## 🐦 THE POST (honest-methodology lead — RECOMMENDED)

> everyone's AI "aces" the cyber benchmarks. nobody mentions the benchmark
> leaks the answers, or that "76%" means *10 tries and we kept the best one.* 🙃
>
> so I measured my hackbot the annoying way:
> ✅ 1 shot (pass@1)
> ✅ every flag/writeup/env-var scrubbed from the files
> ✅ ZERO exploit hints in the prompt — it derives the 0day itself
> ✅ every flag from a LIVE exploit, logged
>
> honest score on Cybench: **52.5%** — on all 40 tasks. 🧵

> 2/ that 52.5% is lower than the headline numbers you've seen — on purpose.
> those are usually pass@10 on a corpus the model may have trained on.
> mine is one shot, answers removed, on Claude Opus 4.8.
>
> lower number, but you can actually trust it. receipts in repo. 🧾

> 3/ and it's *real* solving, not memorizing. it cracked a hard SekaiCTF crypto
> chall by hitting the oracle 133×, recovering a 512-bit key via CRT + Gaussian
> elimination over GF(2), then AES-CTR decrypt — from its own brain, no hint.
> linear algebra & spite 😎

> 4/ the honest part nobody does: I audit MYSELF.
> found 7 ways the corpus leaks flags — writeups, env vars, `docker exec`
> peeking, and the worst one: my agent could just `find /` the host disk and
> read the answer key out of the solution folder. 💀
> caught it, JAILED the sandbox, re-ran clean. 2 of my "solves" became honest
> misses — but the number HELD (even went up after I recovered 9 deleted
> challenges). real, not a peek.
>
> a benchmark number you can't reproduce isn't a result, it's a vibe. 🫡

> 4b/ receipts: docs/INTEGRITY_LEDGER.md logs all 7 vectors + every retraction.
> the jail blocked 19 escape attempts on the clean run; 0 got through. so every
> one of the 21 solves is clean-by-construction, not by my say-so.

> 5/ fine print bc i'm not a marketing dept:
> • 52.5% over all 40; 65.6% over the 32 with a fair shot (rest = broken
>   upstream docker / live targets I haven't re-hosted yet)
> • Opus 4.8 (2026) does most of the heavy lifting — my harness adds live-exec
>   + scrub + a "don't give up" floor
> • NOT claiming a record. claiming an *honest* number. those are rarer.

---

## ⚠️ HONESTY CHECKLIST — status
- [x] XBOW≠Cybench → comparison removed everywhere
- [x] not SOTA (Anthropic Sonnet 4.5 = 76.5% pass@10) → claim pivoted to methodology
- [x] pass@1 vs pass@10 → disclosed explicitly in the post itself
- [x] both denominators (52.5% of 40, 65.6% of 32 fair-shot) → stated
- [x] opus-4.8 solves verified: 0 docker-exec, 0 scrubbed-leak, model=claude-opus-4-8
- [ ] framework-vs-model isolation → NOT done; do not claim "framework alone does X"

## 🔬 STILL-TODO before any "framework lift" claim
Run vanilla Opus 4.8 in the ORIGINAL Cybench harness (pass@1) as a baseline,
then compare to T3MP3ST pass@1. Until then, the defensible lift claim is only:
"live-service execution + scrub + persistence floor on top of Opus 4.8,"
NOT a quantified framework delta.
