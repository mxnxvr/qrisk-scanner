from qrisk.models import Finding, Rating
from qrisk.rules import NIST_2030, NIST_2035, TLS_GROUPS, rate_public_key, rate_signature, rate_ssh_kex, rate_tls12_kex
from qrisk.scoring import CRITICAL_CAP, grade, readiness_score

S, H, Q, C = Rating.QUANTUM_SAFE, Rating.HYBRID, Rating.QUANTUM_VULNERABLE, Rating.CRITICAL


def f(target, category, rating):
    return Finding(target, "tls", category, "x", rating, "", "")


def server(kex: list[Rating], cert=Q, sig=Q, target="a"):
    """A TLS 1.3 server: protocol and AES-GCM are fine; key exchange and certificate vary."""
    return ([f(target, "protocol", S), f(target, "protocol", Q)]          # TLS 1.3 + TLS 1.2
            + [f(target, "cipher", S) for _ in range(3)]                  # AES-GCM, ChaCha20
            + [f(target, "key-exchange", r) for r in kex]
            + [f(target, "certificate-key", cert), f(target, "certificate-signature", sig)])


def test_empty():
    assert readiness_score([]) is None
    assert grade(None) == "No findings"


def test_classical_tls13_server_is_quantum_vulnerable_not_in_transition():
    """Review: a classical TLS 1.3 server scored 55 ("In transition") because sound protocol and
    AES findings were averaged in. Only public-key crypto measures quantum readiness."""
    score = readiness_score(server(kex=[Q, Q]))
    assert score == 25 and grade(score) == "Quantum-vulnerable"


def test_hybrid_never_scores_below_pure_ml_kem():
    hybrid = readiness_score(server(kex=[H], cert=S, sig=S))
    pure = readiness_score(server(kex=[S], cert=S, sig=S))
    assert hybrid == pure == 100


def test_post_quantum_key_exchange_moves_a_server_into_transition():
    # Hybrid key exchange, still-classical certificate: real progress, not finished.
    score = readiness_score(server(kex=[H, Q], cert=Q, sig=Q))
    assert grade(score) in ("Quantum-vulnerable", "In transition") and score > readiness_score(server(kex=[Q]))


def test_hygiene_counts_when_critical():
    findings = server(kex=[S], cert=S, sig=S) + [f("a", "protocol", C)]   # e.g. TLS 1.0 enabled
    assert readiness_score(findings) == CRITICAL_CAP


def test_target_with_only_symmetric_crypto_is_scored_on_it():
    # e.g. a code base that only uses AES-GCM: nothing quantum-breakable, so it scores well.
    assert readiness_score([f("code", "cipher", S), f("code", "cipher", S)]) == 100


def test_categories_and_targets_weighted_equally():
    # 10 classical groups must not outweigh one certificate category; each target counts once.
    a = [f("a", "key-exchange", Q) for _ in range(10)] + [f("a", "certificate-key", S)]
    b = [f("b", "key-exchange", S)]
    assert readiness_score(a + b) == round(((25 + 100) / 2 + 100) / 2)


def test_critical_caps_score():
    findings = [f("a", "key-exchange", S) for _ in range(5)] + [f("a", "certificate-key", C)]
    assert readiness_score(findings) == CRITICAL_CAP
    assert grade(90) == "Quantum-ready"


def test_critical_findings_never_carry_a_future_deadline():
    """Review: static RSA was Critical but labelled 'deprecated after 2030'. Critical means broken now."""
    verdicts = [rate_tls12_kex(k) for k in ("RSA", "DHE", "ECDHE", "DH_anon")]
    verdicts += [rate_public_key("RSA", b) for b in (512, 1024, 2048, 4096)]
    verdicts += [rate_public_key("EC", 192, "secp192r1"), rate_public_key("DSA", 1024), rate_public_key("DH", 1024)]
    verdicts += [rate_signature("x", h, "RSA") for h in ("md5", "sha1", "sha256")]
    verdicts += [rate_ssh_kex(k) for k in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1")]
    verdicts += [v for _, v in TLS_GROUPS.values()]
    for v in verdicts:
        if v.rating is C:
            assert v.nist not in (NIST_2030, NIST_2035), v.reason
