"""Report translations (English and Arabic).

The executive part of the report (headings, summary, ratings, deadlines and
priority actions) is fully translated. Technical reasons stay in English so
algorithm names and terms remain exact. Recommendations are translated when they
are one of the standard ones; anything else falls back to English.
"""

from __future__ import annotations

from .models import Rating
from .rules import (
    REC_AES128, REC_HYBRID_KEEP, REC_KYBER_DRAFT, REC_NONE, REC_PQ_CERT, REC_RSA_KEX, REC_SSH_HOSTKEY,
    REC_SSH_HYBRID, REC_SSH_MAC, REC_SSH_REMOVE, REC_TLS13, REC_TLS_HYBRID, REC_TLS_OLD, REC_WEAK_CIPHER, REC_WEAK_KEY,
    REC_WEAK_SIG,
)
from .scanners import code as _code
from .scanners.config import FIX

LANGUAGES = ("en", "ar")

UI: dict[str, dict[str, str]] = {
    "en": {
        "title": "Quantum Readiness Report",
        "generated": "Generated {generated} by QRisk Scanner {version} · {targets} target(s) · {total} finding(s)",
        "exec_summary": "Executive summary",
        "out_of": "out of 100",
        "found": "We found {total} cryptographic findings across {targets} target(s).",
        "critical": "{n} are weak even today and should be fixed first.",
        "vulnerable": "{n} are safe today but will be broken by a cryptographically relevant quantum computer.",
        "hybrid": "{n} already use hybrid post-quantum protection.",
        "none": "No cryptography was found in the scanned targets.",
        "nist": "NIST deadlines (IR 8547)",
        "now": "Now", "now_label": "Already weak or disallowed",
        "y2030_label": "Deprecated (112-bit: RSA-2048, ffdhe2048, ...)",
        "y2035_label": "All quantum-vulnerable public-key crypto disallowed",
        "priority": "Priority actions",
        "count": "({n} finding{s})",
        "technical": "Technical detail",
        "technical_note": "",
        "scale": "Rating scale:",
        "th_rating": "Rating", "th_asset": "Asset", "th_category": "Category", "th_why": "Why", "th_nist": "NIST",
        "notes": "Notes",
        "footer": ("Score method: public-key findings (key exchange, certificates, signatures, host keys) earn "
                   "100 (quantum-safe or hybrid), 25 (quantum-vulnerable) or 0 (critical) points; protocol, cipher "
                   "and other hygiene findings only count when critical. Points are averaged per category, then per "
                   "target. Any critical finding caps the score at 49. Deadlines follow NIST IR 8547. This report "
                   "is a point-in-time automated assessment, not a full audit."),
    },
    "ar": {
        "title": "تقرير الجاهزية الكمّية",
        "generated": "أُعدّ في {generated} بواسطة QRisk Scanner {version} · عدد الأهداف: {targets} · عدد النتائج: {total}",
        "exec_summary": "الملخص التنفيذي",
        "out_of": "من 100",
        "found": "رصد الفحص {total} عنصرًا تشفيريًا عبر {targets} من الأهداف.",
        "critical": "منها {n} ضعيفة حتى اليوم ويجب معالجتها أولًا.",
        "vulnerable": "و{n} آمنة اليوم لكنها ستُكسر عند ظهور حاسوب كمّي قادر على كسر التشفير.",
        "hybrid": "و{n} تستخدم بالفعل حماية هجينة مقاومة للحوسبة الكمّية.",
        "none": "لم يُعثر على أي تشفير في الأهداف التي تم فحصها.",
        "nist": "المواعيد النهائية لـ NIST ‏(IR 8547)",
        "now": "الآن", "now_label": "ضعيف أو محظور بالفعل",
        "y2030_label": "إيقاف الاعتماد (أمان 112 بت: RSA-2048 و ffdhe2048 وغيرها)",
        "y2035_label": "حظر جميع خوارزميات المفتاح العام المعرّضة للخطر الكمّي",
        "priority": "الإجراءات ذات الأولوية",
        "count": "({n} نتيجة)",
        "technical": "التفاصيل التقنية",
        "technical_note": "تبقى الأسباب التقنية باللغة الإنجليزية للحفاظ على دقة أسماء الخوارزميات والمصطلحات.",
        "scale": "مقياس التصنيف:",
        "th_rating": "التصنيف", "th_asset": "العنصر", "th_category": "الفئة", "th_why": "السبب والتوصية",
        "th_nist": "NIST",
        "notes": "ملاحظات",
        "footer": ("طريقة احتساب الدرجة: تحصل نتائج المفاتيح العامة (تبادل المفاتيح والشهادات والتواقيع ومفاتيح "
                   "الخوادم) على 100 نقطة (آمنة كمّيًا أو هجينة) أو 25 (معرّضة للخطر الكمّي) أو 0 (حرجة)، ولا تُحتسب "
                   "نتائج البروتوكول والتشفير المتماثل وغيرها إلا إذا كانت حرجة. يُحسب المتوسط لكل فئة ثم لكل هدف. "
                   "أي نتيجة حرجة تجعل الحد الأقصى للدرجة 49. المواعيد النهائية وفق NIST IR 8547. هذا التقرير تقييم "
                   "آلي في لحظة زمنية محددة وليس تدقيقًا شاملًا."),
    },
}

RATING_LABEL = {
    "en": {r: r.label for r in Rating},
    "ar": {Rating.CRITICAL: "حرج", Rating.QUANTUM_VULNERABLE: "معرّض للخطر الكمّي",
           Rating.HYBRID: "هجين", Rating.QUANTUM_SAFE: "آمن كمّيًا"},
}
RATING_MEANING = {
    "en": {r: r.meaning for r in Rating},
    "ar": {Rating.CRITICAL: "ضعيف حتى اليوم", Rating.QUANTUM_VULNERABLE: "آمن اليوم، وسيُكسر بالحاسوب الكمّي",
           Rating.HYBRID: "مقاوم للحوسبة الكمّية مع طبقة تقليدية (الانتقال الموصى به)",
           Rating.QUANTUM_SAFE: "مقاوم للحوسبة الكمّية"},
}
GRADE = {
    "ar": {"Quantum-ready": "جاهز كمّيًا", "In transition": "في مرحلة الانتقال",
           "Quantum-vulnerable": "معرّض للخطر الكمّي", "At risk": "في خطر", "No findings": "لا توجد نتائج"},
}
CATEGORY = {
    "ar": {
        "protocol": "البروتوكول", "key-exchange": "تبادل المفاتيح", "cipher": "التشفير المتماثل",
        "certificate-key": "مفتاح الشهادة", "certificate-signature": "توقيع الشهادة",
        "certificate-validity": "صلاحية الشهادة", "host-key": "مفتاح الخادم", "host-key-size": "حجم مفتاح الخادم",
        "private-key": "مفتاح خاص", "public-key": "مفتاح عام", "hash": "دالة التجزئة", "tls-config": "إعداد TLS",
        "secret": "سرّ مكشوف", "signature": "توقيع", "mac": "رمز مصادقة الرسائل", "keystore": "مخزن المفاتيح",
    },
}
NOTE_LEVEL = {"ar": {"info": "معلومة", "warning": "تحذير", "error": "خطأ"}}

_FIX_AR = {
    "nginx": {
        "protocols": "اضبط `ssl_protocols TLSv1.2 TLSv1.3;`",
        "groups": "ضع المجموعة الهجينة أولًا: `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (OpenSSL 3.5+).",
        "ciphers": "استخدم قائمة حديثة، مثل `ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;`",
    },
    "apache": {
        "protocols": "اضبط `SSLProtocol -all +TLSv1.2 +TLSv1.3`",
        "groups": "أضف `SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:prime256v1` (OpenSSL 3.5+).",
        "ciphers": "استخدم قائمة حديثة، مثل `SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20`",
    },
    "openssl": {
        "protocols": "اضبط `MinProtocol = TLSv1.2` في قسم system_default.",
        "groups": "اضبط `Groups = X25519MLKEM768:X25519:prime256v1` (OpenSSL 3.5+).",
        "ciphers": "استخدم `CipherString = DEFAULT:@SECLEVEL=2` أو أعلى.",
    },
}

RECOMMENDATION_AR: dict[str, str] = {
    REC_NONE: "لا يلزم أي إجراء.",
    REC_TLS_HYBRID: ("فعّل تبادل المفاتيح الهجين المقاوم للحوسبة الكمّية باستخدام OpenSSL 3.5 أو أحدث: "
                     "`Groups = X25519MLKEM768:X25519:secp256r1` "
                     "(في nginx: `ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;`)."),
    REC_TLS13: "فعّل TLS 1.3 واجعله المفضّل؛ فتبادل المفاتيح الهجين (X25519MLKEM768) متاح فقط في TLS 1.3.",
    REC_TLS_OLD: "عطّل SSL 3.0 و TLS 1.0 و TLS 1.1، واجعل الحد الأدنى TLS 1.2 مع تفضيل TLS 1.3.",
    REC_HYBRID_KEEP: "وضع انتقالي جيد. اجعل هذه المجموعة أولًا، واستغنِ عن البدائل التقليدية عندما يسمح العملاء بذلك.",
    REC_KYBER_DRAFT: "مسودة Kyber سابقة للمعيار: استبدلها بالمجموعة المعيارية X25519MLKEM768.",
    REC_PQ_CERT: ("أدرج هذه الشهادة في خطة الانتقال إلى شهادات ML-DSA ‏(FIPS 204) حين تدعمها جهة الإصدار والعملاء، "
                  "وأبقِ مدة صلاحية الشهادات قصيرة لتسهيل الاستبدال السريع."),
    REC_WEAK_KEY: "استبدله فورًا بمفتاح RSA بطول 3072 بت أو أكثر أو ECDSA P-256/P-384، ثم خطّط للانتقال إلى ML-DSA.",
    REC_WEAK_SIG: "أعد إصدار الشهادة بتوقيع SHA-256 أو أقوى.",
    REC_RSA_KEX: ("عطّل مجموعات التشفير ذات تبادل مفاتيح RSA الثابت (`TLS_RSA_WITH_*`)؛ فهي تفتقر إلى السرية التامة "
                  "للأمام، ما يسمح بفك تشفير الحركة المسجّلة لاحقًا. استخدم ECDHE في TLS 1.2 و ML-KEM الهجين في TLS 1.3."),
    REC_WEAK_CIPHER: "عطّل هذه الخوارزمية، واسمح فقط بـ AES-GCM و ChaCha20-Poly1305.",
    REC_AES128: "مقبول. يُفضّل AES-256 للبيانات طويلة العمر (يشترطه CNSA 2.0).",
    REC_SSH_HYBRID: ("فعّل `mlkem768x25519-sha256` (OpenSSH 9.9+، وهو الافتراضي في 10.0) أو `sntrup761x25519-sha512` "
                     "(OpenSSH 9.0+) واجعله أولًا في `KexAlgorithms`."),
    REC_SSH_REMOVE: "احذفه من sshd_config ‏(`KexAlgorithms` أو `HostKeyAlgorithms` أو `Ciphers`).",
    REC_SSH_HOSTKEY: ("لا يوجد حتى الآن مفتاح خادم SSH معياري مقاوم للحوسبة الكمّية. فضّل ssh-ed25519، واجعل المفاتيح "
                      "قابلة للتدوير، وتابع عمل OpenSSH على ML-DSA."),
    _code.REC_HASH: ("استخدم SHA-256 أو SHA-3 لأي غرض أمني. وإن كان الاستخدام مجرد تدقيق غير أمني فصرّح بذلك "
                     "(في Python: `hashlib.md5(data, usedforsecurity=False)`)."),
    _code.REC_ECB: "وضع ECB يكشف أنماط البيانات الأصلية. استخدم وضعًا موثّقًا مثل AES-GCM.",
    _code.REC_CIPHER: "استبدلها بـ AES-256-GCM أو ChaCha20-Poly1305.",
    _code.REC_PQ_SIG: ("خطّط للانتقال إلى ML-DSA ‏(FIPS 204)، واجمع عمليات التوقيع خلف واجهة واحدة ليسهل تبديل "
                       "الخوارزمية (المرونة التشفيرية)."),
    _code.REC_PQ_KEX: ("خطّط للانتقال إلى تبادل مفاتيح هجين قائم على ML-KEM (مثل X25519 + ML-KEM-768، FIPS 203)، "
                       "واجمع تبادل المفاتيح خلف واجهة واحدة ليسهل تبديله."),
    _code.REC_TLS: "اشترط TLS 1.2 أو أحدث وفضّل TLS 1.3 (اللازم لتبادل المفاتيح المقاوم للحوسبة الكمّية).",
    _code.REC_VERIFY: "لا تعطّل التحقق من الشهادات خارج الاختبارات المحلية، وأصلح مخزن الثقة بدلًا من ذلك.",
    _code.REC_SECRET: "احذف المفتاح من نظام إدارة الشيفرة، واستبدله بمفتاح جديد، وحمّل المفاتيح من خدمة لإدارة الأسرار.",
    _code.REC_CREATECIPHER: ("الدالة crypto.createCipher تشتق المفاتيح باستخدام MD5 وأُزيلت في Node 22. "
                             "استخدم createCipheriv مع AES-256-GCM."),
    "Renew the certificate now.": "جدّد الشهادة فورًا.",
    REC_SSH_MAC: ("استخدم `hmac-sha2-256-etm@openssh.com` أو `hmac-sha2-512-etm@openssh.com` واحذف رمز المصادقة "
                  "هذا من `MACs` في sshd_config."),
}
for _server, _fixes in FIX.items():
    for _what, _text in _fixes.items():
        RECOMMENDATION_AR[_text] = _FIX_AR[_server][_what]


def ui(lang: str) -> dict[str, str]:
    return UI.get(lang, UI["en"])


def recommendation(text: str, lang: str) -> str:
    return RECOMMENDATION_AR.get(text, text) if lang == "ar" else text


def grade(text: str, lang: str) -> str:
    return GRADE.get(lang, {}).get(text, text)


def category(text: str, lang: str) -> str:
    return CATEGORY.get(lang, {}).get(text, text)


def note_level(text: str, lang: str) -> str:
    return NOTE_LEVEL.get(lang, {}).get(text, text)
