package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Entry point for Destroy AES extension
 * 
 * This extension allows:
 * - Automatically decrypt AES-encrypted requests and responses
 * - Supports modes: CBC, ECB, GCM
 * - Supports padding: PKCS5, PKCS7, NoPadding
 * - Works like AES Killer: decrypts in intercept, encrypts on send
 */
public class BurpExtension implements burp.api.montoya.BurpExtension {
    
    private static final String EXTENSION_NAME = "Destroy AES";
    private static final String VERSION = "1.0.0";
    
    private MontoyaApi api;
    private CryptoConfig config;
    private ProxyHandler proxyHandler;
    private HttpHandler httpHandler;
    private ConfigPanel configPanel;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        
        // Set extension name
        api.extension().setName(EXTENSION_NAME);
        
        // Startup log
        String separator = "============================================================";
        api.logging().logToOutput(separator);
        api.logging().logToOutput(EXTENSION_NAME + " v" + VERSION);
        api.logging().logToOutput("Complete flow: Decrypt in Intercept → Encrypt on send");
        api.logging().logToOutput(separator);
        
        try {
            // Initialize configuration
            config = new CryptoConfig();
            api.logging().logToOutput("✓ Configuration initialized");
            
            // Create configuration UI panel
            configPanel = new ConfigPanel(config, api);
            api.userInterface().registerSuiteTab("Destroy AES", configPanel);
            api.logging().logToOutput("✓ Configuration panel registered");
            
            // Register PROXY handler (for decrypting in intercept)
            proxyHandler = new ProxyHandler(config, api);
            api.proxy().registerRequestHandler(proxyHandler);
            api.proxy().registerResponseHandler(proxyHandler);
            api.logging().logToOutput("✓ Proxy Handler registered (decrypts in intercept)");
            
            // Register HTTP handler (for encrypting before sending)
            httpHandler = new HttpHandler(config, api);
            api.http().registerHttpHandler(httpHandler);
            api.logging().logToOutput("✓ HTTP Handler registered (encrypts before sending)");
            
            // Register context menu for manual encrypt/decrypt
            api.userInterface().registerContextMenuItemsProvider(new MyContextMenuProvider(config, api));
            api.logging().logToOutput("✓ Context menu registered");
            
            api.logging().logToOutput(separator);
            api.logging().logToOutput("EXTENSION LOADED SUCCESSFULLY");
            api.logging().logToOutput("");
            api.logging().logToOutput("WORKFLOW:");
            api.logging().logToOutput("1. Configure the extension in the 'Destroy AES' tab");
            api.logging().logToOutput("2. Intercept requests → you'll see DECRYPTED data");
            api.logging().logToOutput("3. On Forward → automatically encrypted");
            api.logging().logToOutput("4. Server responses → automatically decrypted");
            api.logging().logToOutput(separator);
            
        } catch (Exception e) {
            api.logging().logToError("❌ Error initializing extension: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Context menu provider
     */
    private static class MyContextMenuProvider implements ContextMenuItemsProvider {
        
        private final CryptoConfig config;
        private final MontoyaApi api;
        
        public MyContextMenuProvider(CryptoConfig config, MontoyaApi api) {
            this.config = config;
            this.api = api;
        }
        
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> menuItems = new ArrayList<>();
            
            // Only show in correct context
            if (event.selectedRequestResponses().isEmpty()) {
                return menuItems;
            }
            
            // Option to decrypt selection
            JMenuItem decryptItem = new JMenuItem("Decrypt with AES Master");
            decryptItem.addActionListener(e -> decryptSelection(event));
            menuItems.add(decryptItem);
            
            // Option to encrypt selection
            JMenuItem encryptItem = new JMenuItem("Encrypt with AES Master");
            encryptItem.addActionListener(e -> encryptSelection(event));
            menuItems.add(encryptItem);
            
            return menuItems;
        }
        
        /**
         * Decrypts current selection
         */
        private void decryptSelection(ContextMenuEvent event) {
            try {
                if (!config.isValid()) {
                    api.logging().logToError("Invalid configuration");
                    JOptionPane.showMessageDialog(null,
                        "Configuration is invalid. Please configure the extension first.",
                        "Configuration Error",
                        JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // Get selected text from message component
                String selectedText = getSelectedText(event);
                
                if (selectedText == null || selectedText.isEmpty()) {
                    api.logging().logToError("No text selected");
                    return;
                }
                
                // Decrypt
                String decrypted = CryptoHelper.decrypt(selectedText.trim(), config);
                
                // Show result in dialog
                JOptionPane.showMessageDialog(null,
                    "Decrypted text:\n\n" + decrypted,
                    "Result",
                    JOptionPane.INFORMATION_MESSAGE);
                
                api.logging().logToOutput("Text decrypted from context menu");
                
            } catch (Exception e) {
                api.logging().logToError("Error decrypting: " + e.getMessage());
                JOptionPane.showMessageDialog(null,
                    "Error decrypting:\n\n" + e.getMessage(),
                    "Decryption Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
        
        /**
         * Encrypts current selection
         */
        private void encryptSelection(ContextMenuEvent event) {
            try {
                if (!config.isValid()) {
                    api.logging().logToError("Invalid configuration");
                    JOptionPane.showMessageDialog(null,
                        "Configuration is invalid. Please configure the extension first.",
                        "Configuration Error",
                        JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // Get selected text
                String selectedText = getSelectedText(event);
                
                if (selectedText == null || selectedText.isEmpty()) {
                    api.logging().logToError("No text selected");
                    return;
                }
                
                // Encrypt
                String encrypted = CryptoHelper.encrypt(selectedText.trim(), config);
                
                // Show result in dialog
                JOptionPane.showMessageDialog(null,
                    "Encrypted text (Base64):\n\n" + encrypted,
                    "Result",
                    JOptionPane.INFORMATION_MESSAGE);
                
                api.logging().logToOutput("Text encrypted from context menu");
                
            } catch (Exception e) {
                api.logging().logToError("Error encrypting: " + e.getMessage());
                JOptionPane.showMessageDialog(null,
                    "Error encrypting:\n\n" + e.getMessage(),
                    "Encryption Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
        
        /**
         * Gets selected text from context menu event
         */
        private String getSelectedText(ContextMenuEvent event) {
            // Try to get text from selected message
            if (event.messageEditorRequestResponse().isPresent()) {
                var editor = event.messageEditorRequestResponse().get();
                if (editor.selectionOffsets().isPresent()) {
                    var offsets = editor.selectionOffsets().get();
                    byte[] bytes = editor.requestResponse().request().toByteArray().getBytes();
                    
                    int start = offsets.startIndexInclusive();
                    int end = offsets.endIndexExclusive();
                    
                    if (start >= 0 && end <= bytes.length && start < end) {
                        byte[] selectedBytes = new byte[end - start];
                        System.arraycopy(bytes, start, selectedBytes, 0, end - start);
                        return new String(selectedBytes, java.nio.charset.StandardCharsets.UTF_8);
                    }
                }
            }
            
            return null;
        }
    }
}
