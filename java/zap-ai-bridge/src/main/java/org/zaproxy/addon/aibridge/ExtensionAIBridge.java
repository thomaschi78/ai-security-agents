/*
 * ZAP AI Bridge Extension
 * Provides integration between ZAP and AI Security Agents framework
 */
package org.zaproxy.addon.aibridge;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/**
 * Main extension class for AI Bridge.
 *
 * Provides:
 * - REST API for AI agents to access ZAP payloads
 * - Bridge for reporting AI findings as ZAP alerts
 * - Integration with ZAP's fuzzer payloads
 */
public class ExtensionAIBridge extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionAIBridge.class);

    public static final String NAME = "ExtensionAIBridge";
    public static final String PREFIX = "aibridge";

    private AIBridgeAPI api;
    private PayloadProvider payloadProvider;
    private AlertBridge alertBridge;

    public ExtensionAIBridge() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // Initialize components
        payloadProvider = new PayloadProvider();
        alertBridge = new AlertBridge();
        api = new AIBridgeAPI(this);

        // Register API
        extensionHook.addApiImplementor(api);

        LOGGER.info("AI Bridge extension initialized");
    }

    @Override
    public void unload() {
        super.unload();
        LOGGER.info("AI Bridge extension unloaded");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return "Bridge between ZAP and AI Security Agents framework";
    }

    @Override
    public String getUIName() {
        return "AI Bridge";
    }

    /**
     * Get the payload provider instance.
     */
    public PayloadProvider getPayloadProvider() {
        return payloadProvider;
    }

    /**
     * Get the alert bridge instance.
     */
    public AlertBridge getAlertBridge() {
        return alertBridge;
    }
}
