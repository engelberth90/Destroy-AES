package burp;

import java.util.Base64;

/**
 * Clase para almacenar la configuración de cifrado/descifrado
 */
public class CryptoConfig {
    
    // Configuración del cifrado
    private String mode = "CBC";              // CBC, ECB, GCM
    private String padding = "PKCS7Padding";  // PKCS5Padding, PKCS7Padding, NoPadding
    private int keySize = 256;                // 128, 192, 256
    
    // Claves y vectores
    private String keyBase64 = "";
    private String ivBase64 = "";
    
    // Configuración de parámetros
    private String requestParameter = "data";
    private String responseParameter = "data";
    
    // Flags
    private boolean enabled = false;
    private boolean decryptRequests = true;
    private boolean decryptResponses = true;
    private boolean autoEncrypt = true;
    
    // Formato de datos
    private String dataFormat = "JSON";  // JSON, RAW, FORM
    
    public CryptoConfig() {
    }
    
    // Getters y Setters
    public String getMode() {
        return mode;
    }
    
    public void setMode(String mode) {
        this.mode = mode;
    }
    
    public String getPadding() {
        return padding;
    }
    
    public void setPadding(String padding) {
        this.padding = padding;
    }
    
    public int getKeySize() {
        return keySize;
    }
    
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }
    
    public String getKeyBase64() {
        return keyBase64;
    }
    
    public void setKeyBase64(String keyBase64) {
        this.keyBase64 = keyBase64;
    }
    
    public byte[] getKey() throws Exception {
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new Exception("Key not configured");
        }
        return Base64.getDecoder().decode(keyBase64);
    }
    
    public String getIvBase64() {
        return ivBase64;
    }
    
    public void setIvBase64(String ivBase64) {
        this.ivBase64 = ivBase64;
    }
    
    public byte[] getIv() throws Exception {
        if (!requiresIv()) {
            return null;
        }
        if (ivBase64 == null || ivBase64.isEmpty()) {
            throw new Exception("IV not configured for " + mode + " mode");
        }
        return Base64.getDecoder().decode(ivBase64);
    }
    
    public String getRequestParameter() {
        return requestParameter;
    }
    
    public void setRequestParameter(String requestParameter) {
        this.requestParameter = requestParameter;
    }
    
    public String getResponseParameter() {
        return responseParameter;
    }
    
    public void setResponseParameter(String responseParameter) {
        this.responseParameter = responseParameter;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isDecryptRequests() {
        return decryptRequests;
    }
    
    public void setDecryptRequests(boolean decryptRequests) {
        this.decryptRequests = decryptRequests;
    }
    
    public boolean isDecryptResponses() {
        return decryptResponses;
    }
    
    public void setDecryptResponses(boolean decryptResponses) {
        this.decryptResponses = decryptResponses;
    }
    
    public boolean isAutoEncrypt() {
        return autoEncrypt;
    }
    
    public void setAutoEncrypt(boolean autoEncrypt) {
        this.autoEncrypt = autoEncrypt;
    }
    
    public String getDataFormat() {
        return dataFormat;
    }
    
    public void setDataFormat(String dataFormat) {
        this.dataFormat = dataFormat;
    }
    
    /**
     * Verifica si el modo actual requiere IV
     */
    public boolean requiresIv() {
        return "CBC".equals(mode) || "GCM".equals(mode);
    }
    
    /**
     * Obtiene el algoritmo completo para javax.crypto
     */
    public String getAlgorithm() {
        if ("GCM".equals(mode)) {
            return "AES/GCM/NoPadding";
        }
        return "AES/" + mode + "/" + padding;
    }
    
    /**
     * Valida la configuración actual
     */
    public boolean isValid() {
        try {
            // Verificar que la clave esté configurada
            if (keyBase64 == null || keyBase64.isEmpty()) {
                return false;
            }
            
            // Verificar el tamaño de la clave
            byte[] key = getKey();
            if (key.length * 8 != keySize) {
                return false;
            }
            
            // Verificar IV si es necesario
            if (requiresIv()) {
                if (ivBase64 == null || ivBase64.isEmpty()) {
                    return false;
                }
                byte[] iv = getIv();
                if (iv.length != 16 && !"GCM".equals(mode)) {
                    return false;
                }
                if (iv.length != 12 && "GCM".equals(mode)) {
                    // GCM típicamente usa 12 bytes, pero puede usar 16
                    if (iv.length != 16) {
                        return false;
                    }
                }
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    public String toString() {
        return "CryptoConfig{" +
                "algorithm='" + getAlgorithm() + '\'' +
                ", keySize=" + keySize +
                ", enabled=" + enabled +
                ", decryptRequests=" + decryptRequests +
                ", decryptResponses=" + decryptResponses +
                '}';
    }
}
