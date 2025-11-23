package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helper class para operaciones de cifrado/descifrado AES
 */
public class CryptoHelper {
    
    private static final int GCM_TAG_LENGTH = 128; // 128 bits para GCM authentication tag
    
    /**
     * Descifra datos usando la configuración proporcionada
     */
    public static String decrypt(String encryptedBase64, CryptoConfig config) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedBase64);
        byte[] decryptedBytes = decrypt(encryptedData, config);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    
    /**
     * Descifra bytes usando la configuración proporcionada
     */
    public static byte[] decrypt(byte[] encryptedData, CryptoConfig config) throws Exception {
        Cipher cipher = Cipher.getInstance(config.getAlgorithm());
        SecretKeySpec keySpec = new SecretKeySpec(config.getKey(), "AES");
        
        if ("ECB".equals(config.getMode())) {
            // ECB no usa IV
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        } else if ("CBC".equals(config.getMode())) {
            // CBC usa IV
            IvParameterSpec ivSpec = new IvParameterSpec(config.getIv());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        } else if ("GCM".equals(config.getMode())) {
            // GCM usa IV (nonce) y authentication tag
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, config.getIv());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        } else {
            throw new Exception("Unsupported mode: " + config.getMode());
        }
        
        return cipher.doFinal(encryptedData);
    }
    
    /**
     * Cifra datos usando la configuración proporcionada
     */
    public static String encrypt(String plaintext, CryptoConfig config) throws Exception {
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = encrypt(plaintextBytes, config);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    /**
     * Cifra bytes usando la configuración proporcionada
     */
    public static byte[] encrypt(byte[] plaintextBytes, CryptoConfig config) throws Exception {
        Cipher cipher = Cipher.getInstance(config.getAlgorithm());
        SecretKeySpec keySpec = new SecretKeySpec(config.getKey(), "AES");
        
        if ("ECB".equals(config.getMode())) {
            // ECB no usa IV
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } else if ("CBC".equals(config.getMode())) {
            // CBC usa IV
            IvParameterSpec ivSpec = new IvParameterSpec(config.getIv());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        } else if ("GCM".equals(config.getMode())) {
            // GCM usa IV (nonce) y authentication tag
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, config.getIv());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        } else {
            throw new Exception("Unsupported mode: " + config.getMode());
        }
        
        return cipher.doFinal(plaintextBytes);
    }
    
    /**
     * Genera una clave AES aleatoria del tamaño especificado
     */
    public static String generateKey(int keySize) {
        byte[] key = new byte[keySize / 8];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
    
    /**
     * Genera un IV aleatorio (16 bytes para CBC, 12 bytes recomendado para GCM)
     */
    public static String generateIV(String mode) {
        int ivSize = "GCM".equals(mode) ? 12 : 16;
        byte[] iv = new byte[ivSize];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }
    
    /**
     * Valida que la clave tenga el tamaño correcto
     */
    public static boolean isValidKeySize(String keyBase64, int expectedSize) {
        try {
            byte[] key = Base64.getDecoder().decode(keyBase64);
            return key.length * 8 == expectedSize;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Valida que el IV tenga el tamaño correcto según el modo
     */
    public static boolean isValidIvSize(String ivBase64, String mode) {
        try {
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            if ("GCM".equals(mode)) {
                // GCM puede usar 12 o 16 bytes
                return iv.length == 12 || iv.length == 16;
            } else if ("CBC".equals(mode)) {
                // CBC siempre usa 16 bytes
                return iv.length == 16;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Convierte hex string a Base64
     */
    public static String hexToBase64(String hex) {
        hex = hex.replaceAll("\\s+", "").toLowerCase();
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return Base64.getEncoder().encodeToString(data);
    }
    
    /**
     * Convierte Base64 a hex string
     */
    public static String base64ToHex(String base64) {
        byte[] bytes = Base64.getDecoder().decode(base64);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Prueba de cifrado/descifrado para verificar configuración
     */
    public static boolean testConfiguration(CryptoConfig config) {
        try {
            String testData = "Test123!@#";
            String encrypted = encrypt(testData, config);
            String decrypted = decrypt(encrypted, config);
            return testData.equals(decrypted);
        } catch (Exception e) {
            return false;
        }
    }
}
