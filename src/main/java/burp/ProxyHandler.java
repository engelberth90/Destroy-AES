package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * ProxyHandler - Maneja el tráfico en el Proxy Intercept
 * 
 * Este handler descifra requests ANTES de mostrarlos en el intercept
 * y cifra responses ANTES de enviarlas al cliente
 */
public class ProxyHandler implements burp.api.montoya.proxy.http.ProxyRequestHandler, 
                                      burp.api.montoya.proxy.http.ProxyResponseHandler {
    
    private final CryptoConfig config;
    private final Logging logging;
    private final Gson gson;
    
    public ProxyHandler(CryptoConfig config, MontoyaApi api) {
        this.config = config;
        this.logging = api.logging();
        this.gson = new Gson();
    }
    
    /**
     * Maneja requests interceptados en el Proxy
     * DESCIFRA la data para que el usuario vea texto plano en el intercept
     */
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (!config.isEnabled() || !config.isDecryptRequests()) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        
        try {
            HttpRequest decrypted = decryptRequest(interceptedRequest);
            if (decrypted != null) {
                logging.logToOutput("[PROXY REQUEST] Descifrado para visualización");
                return ProxyRequestReceivedAction.continueWith(decrypted);
            }
        } catch (Exception e) {
            logging.logToError("[PROXY REQUEST] Error: " + e.getMessage());
        }
        
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
    
    /**
     * Maneja requests que salen del Proxy (después del forward)
     * Este método NO hace nada - el HttpHandler cifrará antes de enviar al servidor
     */
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        // Dejar que HttpHandler maneje el cifrado
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
    
    /**
     * Maneja responses interceptados en el Proxy
     * DESCIFRA la response para que el usuario vea texto plano
     */
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (!config.isEnabled() || !config.isDecryptResponses()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        
        try {
            HttpResponse decrypted = decryptResponse(interceptedResponse);
            if (decrypted != null) {
                logging.logToOutput("[PROXY RESPONSE] Descifrado para visualización");
                return ProxyResponseReceivedAction.continueWith(decrypted);
            }
        } catch (Exception e) {
            logging.logToError("[PROXY RESPONSE] Error: " + e.getMessage());
        }
        
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }
    
    /**
     * Maneja responses que salen del Proxy hacia el cliente
     * RE-CIFRA la response para que el cliente la reciba cifrada
     */
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        if (!config.isEnabled() || !config.isAutoEncrypt()) {
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
        
        try {
            HttpResponse encrypted = encryptResponse(interceptedResponse);
            if (encrypted != null) {
                logging.logToOutput("[PROXY RESPONSE] Re-cifrado antes de enviar al cliente");
                return ProxyResponseToBeSentAction.continueWith(encrypted);
            }
        } catch (Exception e) {
            logging.logToError("[PROXY RESPONSE] Error cifrando: " + e.getMessage());
        }
        
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
    
    /**
     * Descifra un request - reemplaza el valor cifrado con texto plano
     * Si el texto descifrado es JSON válido, lo parsea como objeto JSON
     */
    private HttpRequest decryptRequest(HttpRequest request) {
        try {
            String body = request.bodyToString();
            if (body == null || body.isEmpty()) {
                return null;
            }
            
            if ("JSON".equals(config.getDataFormat())) {
                JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();
                String paramName = config.getRequestParameter();
                
                if (jsonObject.has(paramName)) {
                    String encryptedData = jsonObject.get(paramName).getAsString();
                    String decryptedData = CryptoHelper.decrypt(encryptedData, config);
                    
                    // Intentar parsear como JSON. Si es válido, insertarlo como objeto JSON
                    JsonElement parsedJson = tryParseJson(decryptedData);
                    if (parsedJson != null) {
                        // Es JSON válido, insertarlo como objeto JSON (no como string)
                        jsonObject.add(paramName, parsedJson);
                        logging.logToOutput("[PROXY] Request descifrado y parseado como JSON");
                    } else {
                        // No es JSON válido, mantener como string
                        jsonObject.addProperty(paramName, decryptedData);
                        logging.logToOutput("[PROXY] Request descifrado (texto plano)");
                    }
                    
                    String newBody = gson.toJson(jsonObject);
                    return request.withBody(newBody);
                }
            }
        } catch (Exception e) {
            logging.logToError("[PROXY] Error descifrando request: " + e.getMessage());
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
                    String decryptedData = CryptoHelper.decrypt(encryptedData, config);
                    
                    // Intentar parsear como JSON. Si es válido, insertarlo como objeto JSON
                    JsonElement parsedJson = tryParseJson(decryptedData);
                    if (parsedJson != null) {
                        // Es JSON válido, insertarlo como objeto JSON (no como string)
                        jsonObject.add(paramName, parsedJson);
                        logging.logToOutput("[PROXY] Response descifrado y parseado como JSON");
                    } else {
                        // No es JSON válido, mantener como string
                        jsonObject.addProperty(paramName, decryptedData);
                        logging.logToOutput("[PROXY] Response descifrado (texto plano)");
                    }
                    
                    String newBody = gson.toJson(jsonObject);
                    return response.withBody(newBody);
                }
            }
        } catch (Exception e) {
            logging.logToError("[PROXY] Error descifrando response: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Cifra una response - reemplaza texto plano con valor cifrado
     * Si el valor es un objeto JSON, lo convierte a string antes de cifrar
     */
    private HttpResponse encryptResponse(HttpResponse response) {
        try {
            String body = response.bodyToString();
            if (body == null || body.isEmpty()) {
                return null;
            }
            
            if ("JSON".equals(config.getDataFormat())) {
                JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();
                String paramName = config.getResponseParameter();
                
                if (jsonObject.has(paramName)) {
                    JsonElement element = jsonObject.get(paramName);
                    String plainData;
                    
                    // Si es un objeto/array JSON, convertirlo a string
                    if (element.isJsonObject() || element.isJsonArray()) {
                        plainData = gson.toJson(element);
                        logging.logToOutput("[PROXY] Convirtiendo objeto JSON a string para cifrar");
                    } else {
                        plainData = element.getAsString();
                    }
                    
                    // Solo cifrar si parece ser texto plano (no ya cifrado)
                    if (isLikelyPlaintext(plainData)) {
                        // CIFRAR el texto plano
                        String encryptedData = CryptoHelper.encrypt(plainData, config);
                        
                        // REEMPLAZAR con valor cifrado
                        jsonObject.addProperty(paramName, encryptedData);
                        
                        String newBody = gson.toJson(jsonObject);
                        logging.logToOutput("[PROXY] Response cifrado para cliente");
                        
                        return response.withBody(newBody);
                    }
                }
            }
        } catch (Exception e) {
            logging.logToError("[PROXY] Error cifrando response: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Verifica si un string es texto plano (no cifrado Base64)
     */
    private boolean isLikelyPlaintext(String data) {
        if (data == null || data.isEmpty()) {
            return false;
        }
        
        // Si es muy corto (<16 chars), probablemente es plano
        if (data.length() < 16) {
            return true;
        }
        
        // Si contiene caracteres JSON típicos, es texto plano
        if (data.contains("{") || data.contains("[") || data.contains("\"")) {
            return true;
        }
        
        // Si tiene espacios, probablemente es plano
        if (data.contains(" ")) {
            return true;
        }
        
        // Si NO es Base64 válido, es texto plano
        if (!data.matches("^[A-Za-z0-9+/]+=*$")) {
            return true;
        }
        
        // Por defecto, asumir que es texto plano si llegó aquí
        return false;
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
