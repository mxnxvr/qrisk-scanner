// DELIBERATELY INSECURE sample code for the QRisk lab. Do not copy.
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KEM;

public class TokenService {
    public void run() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);                                        // quantum-vulnerable (2030)

        Cipher legacy = Cipher.getInstance("AES");                   // critical: defaults to ECB
        Cipher tdes = Cipher.getInstance("DESede/CBC/PKCS5Padding"); // critical: 3DES
        Cipher good = Cipher.getInstance("AES/GCM/NoPadding");       // quantum-safe

        Signature sig = Signature.getInstance("SHA1withRSA");        // critical: SHA-1 signature
        MessageDigest md = MessageDigest.getInstance("MD5");         // critical

        // Java 24+ (JEP 496): post-quantum key encapsulation
        KeyPairGenerator pq = KeyPairGenerator.getInstance("ML-KEM-768");
    }
}
