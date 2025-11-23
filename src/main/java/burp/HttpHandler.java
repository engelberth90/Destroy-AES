package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * HttpHandler - Maneja el tráfico HTTP que va al servidor
 * 
 * Este handler CIFRA requests antes de enviarlas al servidor
 * y DESCIFRA responses que vienen del servidor
 * 
 * FLUJO COMPLETO:
 * 1. ProxyHandler descifra en intercept → Usuario ve texto plano
 * 2. HttpHandler cifra antes de enviar → Servidor recibe cifrado
 * 3. HttpHandler descifra response → Usuario ve texto plano
 */
public class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    
    private final CryptoConfig config;
    private final Logging logging;
    private final Gson gson;
    
    public HttpHandler(CryptoConfig config, MontoyaApi api) {
        this.config = config;
        this.logging = api.logging();
        this.gson = new Gson();
    }
    
    /**
     * CIFRA el request antes de enviarlo al servidor
     * El ProxyHandler ya lo descifró para visualización,
     * ahora lo ciframos de nuevo para el servidor
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!config.isEnabled() || !config.isAutoEncrypt()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        try {
            HttpRequest encrypted = encryptRequest(requestToBeSent);
            if (encrypted != null) {
                logging.logToOutput("[HTTP] Request cifrado antes de enviar al servidor");
                return RequestToBeSentAction.continueWith(encrypted);
            }
        } catch (Exception e) {
            logging.logToError("[HTTP REQUEST] Error: " + e.getMessage());
        }
        
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }
    
    /**
     * DESCIFRA la response que viene del servidor
     */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!config.isEnabled() || !config.isDecryptResponses()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        try {
            HttpResponse decrypted = decryptResponse(responseReceived);
            if (decrypted != null) {
                logging.logToOutput("[HTTP] Response descifrado del servidor");
                return ResponseReceivedAction.continueWith(decrypted);
            }
        } catch (Exception e) {
            logging.logToError("[HTTP RESPONSE] Error: " + e.getMessage());
        }
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    /**
     * Cifra un request - reemplaza texto plano con valor cifrado
     * Si el valor es un objeto JSON, lo convierte a string antes de cifrar
     */
    private HttpRequest encryptRequest(HttpRequest request) {
        try {
            String body = request.bodyToString();
            if (body == null || body.isEmpty()) {
                return null;
            }
            
            if ("JSON".equals(config.getDataFormat())) {
                JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();
                String paramName = config.getRequestParameter();
                
                if (jsonObject.has(paramName)) {
                    JsonElement element = jsonObject.get(paramName);
                    String plainData;
                    
                    // Si es un objeto/array JSON, convertirlo a string
                    if (element.isJsonObject() || element.isJsonArray()) {
                        plainData = gson.toJson(element);
                        logging.logToOutput("[HTTP] Convirtiendo objeto JSON a string para cifrar");
                    } else {
                        plainData = element.getAsString();
                    }
                    
                    // Verificar si ya está cifrado (Base64)
                    if (isLikelyEncrypted(plainData)) {
                        logging.logToOutput("[HTTP] Request ya parece estar cifrado, omitiendo...");
                        return null;
                    }
                    
                    // CIFRAR el texto plano
                    String encryptedData = CryptoHelper.encrypt(plainData, config);
                    
                    // REEMPLAZAR con valor cifrado
                    jsonObject.addProperty(paramName, encryptedData);
                    
                    String newBody = gson.toJson(jsonObject);
                    logging.logToOutput("[HTTP] Request cifrado antes de enviar al servidor");
                    
                    return request.withBody(newBody);
                }
            }
        } catch (Exception e) {
            logging.logToError("[HTTP] Error cifrando request: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Descifra una response - reemplaza el valor cifrado con texto plano
     * Si el texto descifrado es JSON válido, lo parsea como objeto JSON
     */
    private HttpResponse decryptResponse(HttpResponse response) {
        try {
            String body = response.bodyToString();
            if (body == null || body.isEmpty()) {
                return null;
            }
            
            if ("JSON".equals(config.getDataFormat())) {
                JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();
                String paramName = config.getResponseParameter();
                
                if (jsonObject.has(paramName)) {
                    String encryptedData = jsonObject.get(paramName).getAsString();
                    
                    // Verificar si parece estar cifrado
                    if (!isLikelyEncrypted(encryptedData)) {
                        logging.logToOutput("[HTTP] Response no parece estar cifrado, omitiendo...");
                        return null;
                    }
                    
                    String decryptedData = CryptoHelper.decrypt(encryptedData, config);
                    
                    // Intentar parsear como JSON. Si es válido, insertarlo como objeto JSON
                    JsonElement parsedJson = tryParseJson(decryptedData);
                    if (parsedJson != null) {
                        // Es JSON válido, insertarlo como objeto JSON (no como string)
                        jsonObject.add(paramName, parsedJson);
                        logging.logToOutput("[HTTP] Response descifrado y parseado como JSON");
                    } else {
                        // No es JSON válido, mantener como string
                        jsonObject.addProperty(paramName, decryptedData);
                        logging.logToOutput("[HTTP] Response descifrado (texto plano)");
                    }
                    
                    String newBody = gson.toJson(jsonObject);
                    return response.withBody(newBody);
                }
            }
        } catch (Exception e) {
            logging.logToError("[HTTP] Error descifrando response: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Verifica si un string parece estar cifrado (Base64)
     * Heurística: Base64 típicamente tiene >16 caracteres y mix de mayúsculas/minúsculas
     */
    private boolean isLikelyEncrypted(String data) {
        if (data == null || data.isEmpty()) {
            return false;
        }
        
        // Muy corto para ser cifrado AES (mínimo ~16 chars en Base64)
        if (data.length() < 16) {
            return false;
        }
        
        // Si contiene espacios o saltos, no es Base64
        if (data.contains(" ") || data.contains("\n")) {
            return false;
        }
        
        // Debe ser solo caracteres Base64
        if (!data.matches("^[A-Za-z0-9+/]+=*$")) {
            return false;
        }
        
        // Base64 típicamente tiene mix de mayúsculas/minúsculas/números
        boolean hasUpper = !data.equals(data.toLowerCase());
        boolean hasLower = !data.equals(data.toUpperCase());
        
        return hasUpper || hasLower;
    }
    
    /**
     * Intenta parsear un string como JSON
     * Retorna el JsonElement si es válido, null si no es JSON válido
     */
    private JsonElement tryParseJson(String data) {
        if (data == null || data.trim().isEmpty()) {
            return null;
        }
        
        try {
            String trimmed = data.trim();
            // Verificar que comience con { o [ (JSON válido)
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                return JsonParser.parseString(trimmed);
            }
        } catch (Exception e) {
            // No es JSON válido, retornar null
        }
        
        return null;
    }
}
