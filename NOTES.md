# Engineering notes

Bugs found, design decisions, and what I learned building QRisk. Each entry follows
the same shape: **problem → cause → fix → lesson**, and every bug has a regression
test (see the table at the end).

---

## Found by running the Docker lab

### 1. The scanner couldn't read the lab's own ML-DSA key
- **Problem:** Scanning `lab/nginx/certs` said "Could not parse" for `mldsa.key`, though the ML-DSA *certificate* next to it was rated correctly.
- **Cause:** The Python `cryptography` library can load ML-DSA certificates' metadata but not ML-DSA/ML-KEM private or public keys yet. Offline tests never had a real post-quantum key, only certificates.
- **Fix:** When loading fails, read the algorithm OID from the start of the PKCS#8 / SPKI structure (`2.16.840.1.101.3.4.3.18` = ML-DSA-65) and rate it from that. Added a test with a hand-built PKCS#8 blob.
- **Lesson:** Post-quantum tooling support is uneven. Don't rely on one library to recognise new algorithms; fall back to the standard identifiers. And test against real artefacts, not just synthetic ones.

### 2. The config said 3DES; the server didn't offer it
- **Problem:** `weak-tls` is configured with `DES-CBC3-SHA`, but the live scan found no 3DES suite.
- **Cause:** Alpine's OpenSSL 3.5 no longer offers 3DES, even at `@SECLEVEL=0`, and nginx ignores unknown cipher names without an error.
- **Fix:** No scanner change: the scanner was right. I corrected the lab docs instead.
- **Lesson:** Config scanning (Layer 5) and live scanning (Layer 1) answer different questions: "what did someone ask for?" vs "what does the server actually do?" A real audit needs both, and differences between them are findings in their own right.

### 3. The SSH image didn't build
- **Problem:** `docker compose up --build` failed with `ssh: not found`.
- **Cause:** The Dockerfile ran `ssh -V` to print the version, but only `openssh-server` was installed, not the client.
- **Fix:** Removed the check.
- **Lesson:** I wrote the lab on a machine without Docker. Anything that hasn't actually run is unverified, so say so clearly until it has.

### Result
Every lab server got the rating it was built for: weak → Critical, classical → Quantum-vulnerable, post-quantum → Hybrid / Quantum-safe. The live lab tests now run in CI on every push.

---

## Found while testing against real systems

### 4. False positives when scanning real libraries (24 → 7)
- **Problem:** Scanning pip's vendored libraries flagged 24 "critical" issues, e.g. `ssl.CERT_NONE` and `ssl.PROTOCOL_TLSv1`.
- **Cause:** Libraries *mention* these constants in lookup tables and comparisons (`if mode == ssl.CERT_NONE`) without *using* them.
- **Fix:** Rules now match configuration only: assignments (`= ssl.CERT_NONE`, not `==`), `minimum_version = …`, `SSLContext(PROTOCOL_…)`. A private-key rule needs real base64 after the PEM header, not just the header string. Added a `qrisk: ignore` comment for deliberate cases (QRisk's own TLS scanner lowers its security on purpose).
- **Lesson:** A security tool people learn to ignore is worthless. Measure false positives on real code, not only on test samples.

### 5. Detecting post-quantum TLS without a post-quantum OpenSSL
- **Problem:** Python's bundled OpenSSL (3.0) can't negotiate X25519MLKEM768, so a normal handshake can't tell whether a server supports it.
- **Solution:** QRisk builds its own TLS ClientHello listing the groups to test but with an empty `key_share`. A server that supports one of them must answer with a HelloRetryRequest naming the group it picked. Offering groups and removing each one the server picks lists everything it supports, using only the standard library.
- **Verified against:** Cloudflare's PQ test server (X25519MLKEM768 found) and the lab's OpenSSL 3.5 server.
- **Lesson:** Understanding the protocol lets you measure things your libraries can't do yet.

### 6. TLS 1.2 key exchange: "ECDHE" wasn't specific enough
- **Fix:** Read the ServerKeyExchange message, which isn't encrypted in TLS 1.2, to get the real curve and DH prime size. A 1024-bit DHE server is now flagged critical (Logjam). Verified that GitHub uses x25519 and P-256.

### 7. SSH host-key size without logging in
- **Fix:** Start a real key exchange and stop as soon as the server sends its public host key. Verified: GitHub's RSA host key is 3072 bits.

---

## Bugs in my own code

### 8. `p += u4()`: a Python evaluation-order bug (JKS parser)
- **Problem:** Parsing Java keystores failed with "unpack requires a buffer of 2 bytes".
- **Cause:** `u4()` reads 4 bytes and advances `p` (via `nonlocal`). But `p += u4()` reads the *old* `p` first, then adds the result, wiping out the 4-byte advance.
- **Fix:** `n = u4(); p += n`.
- **Lesson:** Augmented assignment plus a function with side effects on the same variable is a trap. Found it by reproducing outside the test with a minimal input.

### 9. Arabic report: the date printed backwards
- **Problem:** "2026-11-06" showed as "06-11-2026" in the Arabic report.
- **Cause:** In the Unicode bidirectional algorithm, digits that follow Arabic letters are treated as Arabic numbers, and the hyphens between them lose their direction, so the parts reorder.
- **Fix:** Wrap Latin runs (dates, versions) in Unicode isolates (LRI…PDI), and render commands as `<code dir="ltr">`.
- **Lesson:** Localisation means more than translating strings. Test the rendered output visually: I found this from a screenshot, not a unit test.

### 10. PDF export would have been dark
- **Cause:** Headless Edge follows the system dark-mode setting, and the print stylesheet kept the dark colours.
- **Fix:** Apply dark-mode colours to screen only (`@media screen and (prefers-color-scheme: dark)`), so print is always light. (Since the dusk palette, #26, the screen is always dark and `@media print` overrides it with a light paper palette; the test checks that guarantee instead.)

### 11. Tests took 106 seconds instead of 6
- **Cause:** On Windows, `localhost` resolves to `::1` (IPv6) first. The test TLS server listened on IPv4 only, so each of ~40 connections waited ~1 s before falling back.
- **Fix:** Listen on both IPv4 and IPv6 (`dualstack_ipv6=True`).

### 12. `--fail-under` and empty scans (fixed twice, see #16)
- **First fix:** an empty scan made the gate fail, so I made "no findings" pass.
- **That was wrong.** Code review pointed out that an unreachable server *also* produces no findings, so my fix turned "couldn't scan anything" into a green CI build. Revised in #16.

### 13. Line endings would break the lab on Windows
- **Problem:** Git on Windows converts text files to CRLF, and `/bin/sh` inside Linux containers fails on CRLF scripts.
- **Fix:** `.gitattributes` forces LF for shell scripts, Dockerfiles and server configs.

---

## Found in code review

An outside review of the whole code base found these. Several are the kind of bug a security tool must not have.

### 14. XSS in the HTML/PDF report (security)
- **Problem:** The report shows text that comes *from the scanned systems*: certificate names, SSH banners, file paths, code snippets. A malicious server could set its certificate name to `<script>…</script>` and the script would run when the auditor or client opened the report, including inside Chrome while it prints the PDF.
- **Cause:** I used Jinja2's `select_autoescape()`. It only escapes templates whose names end in `.html`, `.htm` or `.xml`, and mine is `report.html.j2`. So escaping was silently **off**. My tests checked the report's content, never that hostile input was neutralised.
- **Fix:** `autoescape=True`. A test builds a real certificate whose name is a `<script>` payload, adds an SSH banner and a file path with an `<img onerror>` payload, and checks both English and Arabic reports show them as escaped text. I wrote the test first and watched it fail. A second test checks the report's own markup (badges, gauge, `<code>` spans) still renders, so escaping didn't break anything that relied on raw HTML.
- **Lesson:** Treat everything a scanner collects as attacker-controlled. "Secure by default" settings need checking. The name `select_autoescape` sounds safe, but its default depends on the file extension.

### 15. One failed target crashed the whole scan
- **Problem:** A TLS scan makes 30–100 handshakes. If a firewall started resetting connections partway through, the exception went all the way up, and the results for *every* target were lost.
- **Fix:** `run_scan` catches errors per target and turns them into error notes. Inside the TLS scan, each step (versions, groups, suites, key exchange, certificate) is guarded separately, so partial results are kept with a warning. The file, code and config scanners turn unreadable files (broken symlinks, permission errors) into notes. Tests simulate a server that starts resetting after 5 handshakes.

### 16. `--fail-under` passed when nothing was scanned
- **Fix:** The gate now fails if any target couldn't be scanned, or if nothing cryptographic was found, and it says why. `--allow-empty` covers the case where finding nothing is expected (QRisk's own CI scans its source code that way).
- **Lesson:** For a CI gate, "no data" must never look like "good data".

### 17. The live TLS scan under-reported the weakest servers
- **Problem:** It only offered 33 suites (no NULL, EXPORT, single DES, …) and only checked them at the highest older TLS version, so a server allowing RC4 only on TLS 1.0 looked clean.
- **Fix:** 68 suites. Every older version the server accepts is checked, and lower versions only look for suites not already found, to keep the handshake count down. A fake TLS server in the tests accepts RC4 and EXPORT suites *only* on TLS 1.0, and the scanner now reports both, plus the static-RSA key exchange behind them.

### 18. SSH MACs were collected but never rated
- **Fix:** One shared rule (`rate_ssh_mac`) used by both the live scan and the `sshd_config` audit. A test checks the two produce identical ratings for the same MAC list: the same "config vs live" lesson as #2.

### 19. Scoring said the wrong thing
- A classical TLS 1.3 server scored 55 ("In transition") because sound protocol and AES findings were averaged in. Now only public-key categories measure readiness; hygiene categories count only when critical. The same server scores 25 ("Quantum-vulnerable").
- Hybrid scored 75 and pure ML-KEM 100, but hybrid is the recommended deployment. Both now earn 100.
- Static RSA was rated Critical but labelled "deprecated after 2030". It's now labelled "Removed in TLS 1.3". A test checks that no critical verdict carries a future deadline.

### 20. Config scans could read the scanning machine's own files
- **Problem:** Absolute `include` paths and relative paths that climbed up to 4 parent folders could pull, say, the auditor's own `/etc/ssl` certificates into a client's report.
- **Fix:** Includes, certificate paths and host keys outside the scanned folder are skipped with a note, unless `--config-follow-external` is given.

### 21. PDF export broke when Edge updated (found while fixing #14)
- **Problem:** The PDF tests started failing overnight. Edge 157 returns before the PDF is written: it hands the job to a background process. My code checked for the file immediately and deleted the temp folder Edge was still reading from.
- **Fix:** Wait until the PDF exists and its size stops changing, and only then clean up the temp folder.
- **Lesson:** Anything that drives an external program depends on that program's version. Tests that really run it (rather than mocking it) are what caught this.

### 22. Lab scans took 30–40 seconds per server (the same bug as #11, in the product)
- **Problem:** The 5 live lab tests took 109 s, while scanning GitHub took about 1 s.
- **Investigation:** I timed every network call. *Every* TLS probe took exactly 2.0 s, while the SSH scans took 0.0 s. The difference: the TLS tests used `localhost` and the SSH tests used `127.0.0.1`.
- **Cause:** On Windows, `localhost` resolves to IPv6 `::1` first, and Docker published the lab on IPv4 only. Each of the 30–40 connections per scan tried IPv6, waited ~2 s for it to fail, then fell back to IPv4. I'd hit exactly this in #11 but only fixed the *test server* (by making it listen on both), which hid the same flaw in the scanner.
- **Fix:** Resolve once per scan, try every address in parallel ("Happy Eyeballs", RFC 8305), and connect straight to the first that answers. SNI and certificate checks still use the hostname. Lab scans went from 30–40 s to 0.0–0.3 s, and the live test run from 109 s to 2.3 s. It also helps real hosts with a broken IPv6 path.
- **Lesson:** When you fix a symptom in a test fixture, ask whether the product has the same problem. Here, the earlier workaround in the test fixture hid the real bug. And measure before guessing: one timing run pointed straight at it.

### 23. Two rating colours looked the same (accessibility)
- **Problem:** In the report, *Hybrid* was gold (`#b08f00`) and *Quantum-vulnerable* orange (`#e8710a`). Found while making charts for the study guide: a colour-validation script flagged the pair as almost indistinguishable for colour-blind readers (OKLab ΔE 2.3) and hard even for normal vision (11.6, where 15 is the floor). The terminal had the same problem (yellow vs dark orange).
- **Fix:** Hybrid is now blue in light mode, dark mode and the terminal. The light orange and the dark-mode red/amber were re-stepped until every check passed: lightness band, chroma, colour-blind separation, normal-vision separation, and 3:1 contrast on the card.
- **Lesson:** Colour is measurable, so measure it instead of judging by eye. A security report is read by people who must not mix up “broken by quantum” with “already protected”. Ratings also always appear as labelled badges, so colour is never the only signal.

### 24. The summary crashed when output was redirected on Windows (found by CI)
- **Problem:** The first GitHub Actions run failed the CLI smoke test on every Windows job with `UnicodeEncodeError: 'charmap' codec can't encode character '●'`. It never happened locally because a Windows terminal handles Unicode, but a redirected stream (`qrisk scan … > out.txt`, or CI capturing output) falls back to cp1252, which has no `●`.
- **Fix:** The summary uses `*` when the output encoding can't show `●`, and the CLI sets `errors="replace"` on stdout/stderr so any other unencodable character in a finding is replaced instead of aborting the scan.
- **Lesson:** "Works in my terminal" is not "works". Output encoding is part of a CLI's interface; test it the way scripts and CI use it (piped), not only the way you run it by hand.

### 25. A test assumed Python's OpenSSL could never do post-quantum TLS (found by CI)
- **Problem:** `test_scan_local_server` failed on all Linux jobs and on Windows/Python 3.13, but passed locally. The test server is Python's own `ssl` module, and the test expected the scanner to warn "no post-quantum key exchange". GitHub's newer Python builds ship **OpenSSL 3.5, which supports ML-KEM**, so the server really offered X25519MLKEM768, the scanner correctly found it, and the warning was rightly absent. Local Pythons have OpenSSL 3.0.
- **Fix:** The test now asks which OpenSSL it is running on: with 3.5+ the scanner must report the hybrid group and rate it Hybrid; with older versions it must find no PQ group and warn.
- **Lesson:** The scanner was right and the test was wrong: it hard-coded a fact about the environment ("OpenSSL has no ML-KEM") that stopped being true. Post-quantum support is arriving in ordinary libraries right now, which is exactly the migration this tool measures. Tests should assert behaviour relative to the environment, not a snapshot of it. Reading the CI log (with `gh run view --log-failed`) found this in a minute after guessing had pointed at the wrong thing (Chrome).

### 26. Re-theming the report without undoing #10 and #23
- **Change:** The report and terminal now use the "dusk" palette of my portfolio site (plum, cream, coral; amber, periwinkle and mint for the ratings). The screen is always dark, like the site. Print and PDF get a light "paper" version of the same hues.
- **What could have broken:** #10 (a dark PDF) and #23 (indistinguishable ratings). Coral, the site's accent, could not be the Critical colour: it is only ΔE 10.9 from amber. Critical became a rose (`#e8576b`); the print palette was found by a small search over shades for the best worst-case colour-blind separation that still passes contrast.
- **Fix to the checks:** Test #23 now also simulates protanopia, deuteranopia and tritanopia (Machado 2009) and requires every rating pair to stay ≥ 8 apart, with ≥ 4.5:1 contrast because badge text is small. Both dusk palettes beat the old validated one (worst case 9.6 / 9.8 vs 2.8). Test #10 now checks that the light palette lives in `@media print`; the generated PDFs were checked to contain only the paper colours.
- **Lesson:** A visual change is a regression risk like any other. Encode the properties you care about (contrast, separation, print is light) as tests, then the look can change freely.

### 27. A Critical finding was labelled "no quantum deadline" (found by a reader)
- **Problem:** A PQC engineer commenting on the project's LinkedIn post argued that a quantum-deadline axis files classically broken crypto (3DES, TLS 1.0) under "no quantum deadline", next to AES-256. For 3DES and TLS 1.0 that wasn't true: the rating axis already has **Critical** ("weak even today"), which sorts first, caps the score at 49 and fills the report's "Now" box. But the check turned up one real case: SSH `aes128-cbc` was rated Critical (CVE-2008-5161) while its deadline column said *"Approved symmetric algorithm (no quantum deadline)"*: the calmest label on the most urgent kind of finding.
- **Cause:** The deadline label described the *algorithm* (AES is approved) rather than the *finding* (CBC in SSH is exploitable). The earlier test (#19) only stopped Critical findings carrying a *future* deadline, and only sampled keys, signatures and key exchange, never ciphers or MACs.
- **Fix:** A new label, "Insecure today (classical attack): fix now, a quantum deadline does not apply", for findings that are broken for non-quantum reasons. A test runs every rule family, ciphers, SSH ciphers, MACs, host keys and protocol versions included, and fails if any Critical verdict is labelled approved, deadline-free or with a future deadline. It failed before the fix.
- **Lesson:** Two axes only help if they never contradict each other. Outside review finds what you stopped seeing, and even a critique built on a wrong premise can point at a real bug: check the claim against the code before agreeing or dismissing it.

---

## Regression tests

Every bug above has a test that fails if it comes back.

| # | Bug | Test |
|---|---|---|
| 1 | ML-DSA private key not recognised | `test_file_scan.py::test_post_quantum_private_key_identified_by_oid` |
| 2 | Config vs live (3DES) | `test_lab.py::test_lab_configs_rate_as_promised` (config side) |
| 3 | SSH image build | the CI `lab` job builds every image |
| 4 | False positives on real code | `test_code_scan.py::test_python_rules` (comparisons, suppression), `test_secrets_and_skipped_dirs` (bare PEM header) |
| 5–7 | PQ TLS, TLS 1.2 curves/DHE, SSH host key | `test_tls_scan.py`, `test_ssh_scan.py` (local servers), `test_tlswire.py` (HelloRetryRequest parsing) |
| 8 | `p += u4()` in the JKS parser | `test_regressions.py::test_08_…`, checked by putting the bug back: the test fails |
| 9 | Backwards date in Arabic | `test_regressions.py::test_09_…` (see below) |
| 10 | Dark PDF | `test_regressions.py::test_10_…` (the print palette is light and lives in `@media print`) |
| 11 | Slow tests (IPv6 `localhost`) | none: it's a test-speed issue, visible as the suite's run time |
| 12, 16 | `--fail-under` and empty / failed scans | `test_regressions.py::test_12_…` (empty fails unless `--allow-empty`; unreachable target fails) |
| 13 | CRLF in lab files | `test_regressions.py::test_13_…` asks `git check-attr`, i.e. what a fresh clone gets |
| 14 | Report XSS | `test_report_security.py` (written first, failed before the fix) |
| 15 | One target crashes the scan | `test_robustness.py::test_failing_target_…`, `test_tls_keeps_partial_results_…`, `test_config_unreadable_file_…` |
| 17 | Missing / per-version cipher suites | `test_robustness.py::test_weak_suites_allowed_only_on_tls10_are_found`, `test_dangerous_suites_are_offered` |
| 18 | SSH MACs unrated | `test_ssh_scan.py::test_live_scan_rates_macs_like_the_config_scan` |
| 19 | Scoring | `test_scoring.py` (classical TLS 1.3 = 25, hybrid = pure ML-KEM, no critical with a future deadline) |
| 20 | Includes outside the folder | `test_robustness.py::test_external_includes_need_an_explicit_flag` |
| 21 | Edge returns before the PDF exists | `test_i18n_pdf.py::test_pdf_export` (runs the real browser) |
| 22 | `localhost` → dead IPv6 → 2 s per connection | `test_robustness.py::test_localhost_scan_of_ipv4_only_server_is_fast` (IPv4-only server scanned as `localhost`) |
| 23, 26 | Rating colours too similar | `test_regressions.py::test_23_…` (screen and print palettes: OKLab ΔE ≥ 15 between neighbouring ratings, ≥ 4.5:1 contrast, and every pair ≥ 8 apart under simulated protanopia, deuteranopia and tritanopia; the old gold/orange pair and the pre-dusk palette are shown to fail) |
| 24 | `●` crashed piped output on Windows | `test_regressions.py::test_24_…` (runs the CLI as a subprocess with cp1252 output; fails with the bug put back) and the CI smoke test |
| 25 | Test assumed no ML-KEM in OpenSSL | `test_tls_scan.py::test_scan_local_server` (checks the PQ result against `ssl.OPENSSL_VERSION_INFO`; CI covers both OpenSSL 3.0 and 3.5) |
| 27 | Critical labelled "no quantum deadline" | `test_scoring.py::test_critical_findings_are_never_labelled_approved_or_deadline_free` (every rule family; failed before the fix) |

Integration tests that need the Docker lab are marked `lab` and **skip** (with the command to start the lab) when it isn't running: a fresh clone shows 94 passed, 5 skipped. CI sets `QRISK_LAB_REQUIRED=1` in its lab job so a lab that fails to start fails the build instead of quietly skipping.

**How could a test have caught #9?** My first test only checked that the fix's marker character was in the HTML. That proves the fix is *present*, not that it *works*. The bug lived in how the text is displayed, so the test now runs the same Unicode bidirectional algorithm browsers use (`python-bidi`) over the rendered line and checks the reader sees `2026-11-06`. A second test removes the isolates and confirms the same check then sees `06-11-2026`, the bug from the screenshot, so the test is proven able to fail. General lesson: test the behaviour the user experiences, not the implementation detail of the fix.

---

## Design decisions worth explaining

- **Score:** findings are averaged per category, then per target, so 15 cipher suites don't outweigh one certificate. Any critical finding caps the score at 49: nothing is "quantum-ready" if it's broken today.
- **CBOM:** CycloneDX 1.6, validated against the official schema in tests, because an inventory other tools can't read is just a report.
- **PDF via the installed browser:** no new dependency, and it shapes Arabic text correctly, which pure-Python PDF libraries don't.
- **Arabic report:** the executive part is translated, while technical reasons stay in English so algorithm names stay exact, which matches how Gulf security reports are usually written.
