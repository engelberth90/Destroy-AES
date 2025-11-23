package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Configuration panel for the extension
 */
public class ConfigPanel extends JPanel {
    
    private final CryptoConfig config;
    private final Logging logging;
    
    // UI Components
    private JCheckBox enabledCheckbox;
    private JCheckBox decryptRequestsCheckbox;
    private JCheckBox decryptResponsesCheckbox;
    private JCheckBox autoEncryptCheckbox;
    
    private JComboBox<String> modeComboBox;
    private JComboBox<String> paddingComboBox;
    private JComboBox<Integer> keySizeComboBox;
    private JComboBox<String> dataFormatComboBox;
    
    private JTextField keyField;
    private JTextField ivField;
    private JTextField requestParamField;
    private JTextField responseParamField;
    
    private JButton generateKeyButton;
    private JButton generateIvButton;
    private JButton testConfigButton;
    private JButton saveButton;
    
    private JLabel statusLabel;
    
    public ConfigPanel(CryptoConfig config, MontoyaApi api) {
        this.config = config;
        this.logging = api.logging();
        
        setLayout(new BorderLayout(5, 5));
        setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Main panel with scroll
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        
        // Sections
        mainPanel.add(createStatusPanel());
        mainPanel.add(Box.createVerticalStrut(5));
        mainPanel.add(createCryptoPanel());
        mainPanel.add(Box.createVerticalStrut(5));
        mainPanel.add(createKeysPanel());
        mainPanel.add(Box.createVerticalStrut(5));
        mainPanel.add(createParametersPanel());
        mainPanel.add(Box.createVerticalStrut(5));
        mainPanel.add(createActionsPanel());
        
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        add(scrollPane, BorderLayout.CENTER);
        
        // Load current values
        loadConfigToUI();
    }
    
    /**
     * Extension status panel
     */
    private JPanel createStatusPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Status"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        enabledCheckbox = new JCheckBox("Extension Enabled", config.isEnabled());
        enabledCheckbox.setFont(new Font("Arial", Font.BOLD, 13));
        enabledCheckbox.addActionListener(e -> updateStatus());
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(enabledCheckbox, gbc);
        
        statusLabel = new JLabel();
        statusLabel.setFont(new Font("Arial", Font.PLAIN, 11));
        updateStatus();
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(statusLabel, gbc);
        
        return panel;
    }
    
    /**
     * Encryption configuration panel
     */
    private JPanel createCryptoPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Encryption Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Mode
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(new JLabel("Mode:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        modeComboBox = new JComboBox<>(new String[]{"CBC", "ECB", "GCM"});
        modeComboBox.addActionListener(e -> onModeChanged());
        panel.add(modeComboBox, gbc);
        
        // Padding
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("Padding:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        paddingComboBox = new JComboBox<>(new String[]{"PKCS5Padding", "PKCS7Padding", "NoPadding"});
        panel.add(paddingComboBox, gbc);
        
        // Key Size
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        panel.add(new JLabel("Key Size:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        keySizeComboBox = new JComboBox<>(new Integer[]{128, 192, 256});
        panel.add(keySizeComboBox, gbc);
        
        // Data Format
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        panel.add(new JLabel("Data Format:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        dataFormatComboBox = new JComboBox<>(new String[]{"JSON", "RAW", "FORM"});
        panel.add(dataFormatComboBox, gbc);
        
        // Options
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        decryptRequestsCheckbox = new JCheckBox("Decrypt Requests", config.isDecryptRequests());
        panel.add(decryptRequestsCheckbox, gbc);
        
        gbc.gridy = 5;
        decryptResponsesCheckbox = new JCheckBox("Decrypt Responses", config.isDecryptResponses());
        panel.add(decryptResponsesCheckbox, gbc);
        
        gbc.gridy = 6;
        autoEncryptCheckbox = new JCheckBox("Auto-encrypt on modify", config.isAutoEncrypt());
        panel.add(autoEncryptCheckbox, gbc);
        
        return panel;
    }
    
    /**
     * Keys and IVs panel
     */
    private JPanel createKeysPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Keys and Vectors"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Key
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(new JLabel("Key (Base64):"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        keyField = new JTextField(25);
        panel.add(keyField, gbc);
        
        gbc.gridx = 2; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        generateKeyButton = new JButton("Generate");
        generateKeyButton.addActionListener(e -> generateKey());
        panel.add(generateKeyButton, gbc);
        
        // IV
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("IV (Base64):"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        ivField = new JTextField(25);
        panel.add(ivField, gbc);
        
        gbc.gridx = 2; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        generateIvButton = new JButton("Generate");
        generateIvButton.addActionListener(e -> generateIv());
        panel.add(generateIvButton, gbc);
        
        return panel;
    }
    
    /**
     * Parameters panel
     */
    private JPanel createParametersPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Parameters"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Request parameter
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(new JLabel("Request Parameter:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        requestParamField = new JTextField(15);
        panel.add(requestParamField, gbc);
        
        // Response parameter
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("Response Parameter:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        responseParamField = new JTextField(15);
        panel.add(responseParamField, gbc);
        
        // Info
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel infoLabel = new JLabel("<html><i>JSON field name containing encrypted data</i></html>");
        infoLabel.setFont(new Font("Arial", Font.PLAIN, 10));
        infoLabel.setForeground(Color.GRAY);
        panel.add(infoLabel, gbc);
        
        return panel;
    }
    
    /**
     * Actions panel
     */
    private JPanel createActionsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        
        testConfigButton = new JButton("🧪 Test Configuration");
        testConfigButton.addActionListener(e -> testConfiguration());
        panel.add(testConfigButton);
        
        saveButton = new JButton("💾 Save Configuration");
        saveButton.addActionListener(e -> saveConfiguration());
        panel.add(saveButton);
        
        return panel;
    }
    
    /**
     * Loads current configuration to UI
     */
    private void loadConfigToUI() {
        enabledCheckbox.setSelected(config.isEnabled());
        decryptRequestsCheckbox.setSelected(config.isDecryptRequests());
        decryptResponsesCheckbox.setSelected(config.isDecryptResponses());
        autoEncryptCheckbox.setSelected(config.isAutoEncrypt());
        
        modeComboBox.setSelectedItem(config.getMode());
        paddingComboBox.setSelectedItem(config.getPadding());
        keySizeComboBox.setSelectedItem(config.getKeySize());
        dataFormatComboBox.setSelectedItem(config.getDataFormat());
        
        keyField.setText(config.getKeyBase64());
        ivField.setText(config.getIvBase64());
        requestParamField.setText(config.getRequestParameter());
        responseParamField.setText(config.getResponseParameter());
        
        onModeChanged();
    }
    
    /**
     * Saves UI configuration to config object
     */
    private void saveConfiguration() {
        try {
            config.setEnabled(enabledCheckbox.isSelected());
            config.setDecryptRequests(decryptRequestsCheckbox.isSelected());
            config.setDecryptResponses(decryptResponsesCheckbox.isSelected());
            config.setAutoEncrypt(autoEncryptCheckbox.isSelected());
            
            config.setMode((String) modeComboBox.getSelectedItem());
            config.setPadding((String) paddingComboBox.getSelectedItem());
            config.setKeySize((Integer) keySizeComboBox.getSelectedItem());
            config.setDataFormat((String) dataFormatComboBox.getSelectedItem());
            
            config.setKeyBase64(keyField.getText().trim());
            config.setIvBase64(ivField.getText().trim());
            config.setRequestParameter(requestParamField.getText().trim());
            config.setResponseParameter(responseParamField.getText().trim());
            
            updateStatus();
            
            if (config.isValid()) {
                JOptionPane.showMessageDialog(this,
                        "✅ Configuration saved successfully",
                        "Success",
                        JOptionPane.INFORMATION_MESSAGE);
                logging.logToOutput("Configuration saved successfully");
            } else {
                JOptionPane.showMessageDialog(this,
                        "⚠️ Configuration saved, but has validation errors",
                        "Warning",
                        JOptionPane.WARNING_MESSAGE);
            }
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "❌ Error saving: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            logging.logToError("Error saving configuration: " + e.getMessage());
        }
    }
    
    /**
     * Tests current configuration
     */
    private void testConfiguration() {
        saveConfiguration(); // Save first
        
        if (!config.isValid()) {
            JOptionPane.showMessageDialog(this,
                    "❌ Invalid configuration. Check all fields.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        boolean success = CryptoHelper.testConfiguration(config);
        
        if (success) {
            JOptionPane.showMessageDialog(this,
                    "✅ Test successful!\n\nConfiguration works correctly.",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
            logging.logToOutput("Configuration test passed");
        } else {
            JOptionPane.showMessageDialog(this,
                    "❌ Test failed.\n\nVerify key, IV and algorithm.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            logging.logToError("Configuration test failed");
        }
    }
    
    /**
     * Generates random key
     */
    private void generateKey() {
        int keySize = (Integer) keySizeComboBox.getSelectedItem();
        String key = CryptoHelper.generateKey(keySize);
        keyField.setText(key);
        logging.logToOutput("Generated new " + keySize + "-bit key");
    }
    
    /**
     * Generates random IV
     */
    private void generateIv() {
        String mode = (String) modeComboBox.getSelectedItem();
        String iv = CryptoHelper.generateIV(mode);
        ivField.setText(iv);
        logging.logToOutput("Generated new IV for " + mode + " mode");
    }
    
    /**
     * Triggered when encryption mode changes
     */
    private void onModeChanged() {
        String mode = (String) modeComboBox.getSelectedItem();
        
        // GCM doesn't use traditional padding
        if ("GCM".equals(mode)) {
            paddingComboBox.setSelectedItem("NoPadding");
            paddingComboBox.setEnabled(false);
        } else {
            paddingComboBox.setEnabled(true);
        }
        
        // ECB doesn't use IV
        boolean requiresIv = !"ECB".equals(mode);
        ivField.setEnabled(requiresIv);
        generateIvButton.setEnabled(requiresIv);
        
        if (!requiresIv) {
            ivField.setBackground(Color.LIGHT_GRAY);
        } else {
            ivField.setBackground(Color.WHITE);
        }
    }
    
    /**
     * Updates status label
     */
    private void updateStatus() {
        boolean enabled = enabledCheckbox.isSelected();
        String status;
        Color color;
        
        if (!enabled) {
            status = "<html><b>Extension DISABLED</b></html>";
            color = Color.RED;
        } else if (config.isValid()) {
            status = "<html><b>Extension ACTIVE and properly configured</b></html>";
            color = new Color(0, 150, 0);
        } else {
            status = "<html><b>Extension active but requires configuration</b></html>";
            color = Color.ORANGE;
        }
        
        statusLabel.setText(status);
        statusLabel.setForeground(color);
        // Ensure HTML is rendered properly
        statusLabel.setVerticalAlignment(SwingConstants.TOP);
    }
}
