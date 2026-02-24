/*
 * Alert Bridge
 * Converts AI findings to ZAP alerts
 */
package org.zaproxy.addon.aibridge;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Bridge for creating ZAP alerts from AI findings.
 *
 * Maps AI confidence/severity to ZAP's alert system:
 * - Risk: 0=Info, 1=Low, 2=Medium, 3=High
 * - Confidence: 0=FP, 1=Low, 2=Medium, 3=High, 4=Confirmed
 */
public class AlertBridge {

    private static final Logger LOGGER = LogManager.getLogger(AlertBridge.class);

    private int alertsCreated = 0;

    // AI vulnerability type to plugin ID mapping
    private static final int AI_SQLI_PLUGIN_ID = 100001;
    private static final int AI_XSS_PLUGIN_ID = 100002;
    private static final int AI_CMDI_PLUGIN_ID = 100003;
    private static final int AI_LFI_PLUGIN_ID = 100004;
    private static final int AI_SSRF_PLUGIN_ID = 100005;
    private static final int AI_XXE_PLUGIN_ID = 100006;
    private static final int AI_LOG4SHELL_PLUGIN_ID = 100007;
    private static final int AI_CSRF_PLUGIN_ID = 100008;
    private static final int AI_SSTI_PLUGIN_ID = 100009;
    private static final int AI_PATH_TRAVERSAL_PLUGIN_ID = 100010;
    private static final int AI_GENERIC_PLUGIN_ID = 100000;

    /**
     * Create a ZAP alert from AI finding data.
     *
     * @param url Target URL
     * @param name Alert name
     * @param risk Risk level (0-3)
     * @param confidence Confidence level (0-4)
     * @param description Alert description
     * @param param Vulnerable parameter
     * @param attack Attack payload used
     * @param evidence Evidence of vulnerability
     * @param cweid CWE ID
     */
    public void createAlert(
            String url,
            String name,
            int risk,
            int confidence,
            String description,
            String param,
            String attack,
            String evidence,
            int cweid) {

        try {
            Alert alert = new Alert(getPluginId(name), risk, confidence, name);

            alert.setUri(url);
            alert.setDescription(description);
            alert.setParam(param);
            alert.setAttack(attack);
            alert.setEvidence(evidence);
            alert.setCweId(cweid);
            alert.setSource(Alert.Source.TOOL);

            // Set solution and reference based on CWE
            alert.setSolution(getSolution(cweid));
            alert.setReference(getReference(cweid));

            // Add to ZAP's alert database
            // Note: In a real implementation, this would use ExtensionAlert
            // For now, we log the alert creation
            LOGGER.info("Created AI alert: {} for {} (CWE-{})", name, url, cweid);

            alertsCreated++;

        } catch (Exception e) {
            LOGGER.error("Failed to create alert for {}", url, e);
            throw new RuntimeException("Alert creation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Get plugin ID based on vulnerability type in name.
     */
    private int getPluginId(String name) {
        String lower = name.toLowerCase();

        if (lower.contains("sql") || lower.contains("sqli")) {
            return AI_SQLI_PLUGIN_ID;
        } else if (lower.contains("xss") || lower.contains("cross-site scripting")) {
            return AI_XSS_PLUGIN_ID;
        } else if (lower.contains("cmdi") || lower.contains("command")) {
            return AI_CMDI_PLUGIN_ID;
        } else if (lower.contains("lfi") || lower.contains("file inclusion")) {
            return AI_LFI_PLUGIN_ID;
        } else if (lower.contains("ssrf")) {
            return AI_SSRF_PLUGIN_ID;
        } else if (lower.contains("xxe") || lower.contains("xml")) {
            return AI_XXE_PLUGIN_ID;
        } else if (lower.contains("log4") || lower.contains("jndi")) {
            return AI_LOG4SHELL_PLUGIN_ID;
        } else if (lower.contains("csrf")) {
            return AI_CSRF_PLUGIN_ID;
        } else if (lower.contains("ssti") || lower.contains("template")) {
            return AI_SSTI_PLUGIN_ID;
        } else if (lower.contains("path") || lower.contains("traversal")) {
            return AI_PATH_TRAVERSAL_PLUGIN_ID;
        }

        return AI_GENERIC_PLUGIN_ID;
    }

    /**
     * Get solution text based on CWE ID.
     */
    private String getSolution(int cweid) {
        switch (cweid) {
            case 89:
                return "Use parameterized queries or prepared statements. Validate and sanitize all user input.";
            case 79:
                return "Encode output data, implement Content-Security-Policy, validate input.";
            case 78:
                return "Avoid shell commands, use safe APIs, validate and sanitize input.";
            case 98:
            case 22:
                return "Use allowlists for file paths, validate input, avoid user-controlled paths.";
            case 918:
                return "Use allowlists for URLs, disable unnecessary protocols, validate input.";
            case 611:
                return "Disable external entities in XML parsers, validate input.";
            case 917:
                return "Update Log4j to 2.17.1+, disable JNDI lookups.";
            case 352:
                return "Implement CSRF tokens, use SameSite cookies, validate origin.";
            case 1336:
                return "Use logic-less templates, sandbox template execution, validate input.";
            default:
                return "Review and address the vulnerability according to security best practices.";
        }
    }

    /**
     * Get reference URL based on CWE ID.
     */
    private String getReference(int cweid) {
        return String.format("https://cwe.mitre.org/data/definitions/%d.html", cweid);
    }

    /**
     * Get count of alerts created.
     */
    public int getAlertsCreated() {
        return alertsCreated;
    }
}
