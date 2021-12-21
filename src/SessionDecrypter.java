import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionDecrypter {

    private SessionKey key;
    private Cipher cipher;
    private IvParameterSpec iv;
    public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.key = new SessionKey(keybytes);
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.iv = new IvParameterSpec(ivbytes);
    }

    CipherInputStream openCipherInputStream(InputStream input) throws InvalidAlgorithmParameterException, InvalidKeyException {
        this.cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(),iv);
        CipherInputStream stream = new CipherInputStream(input, this.cipher);
        return stream;
    }
}
