/*
 * ZAP AI Bridge API
 * REST API endpoints for AI agent integration
 */
package org.zaproxy.addon.aibridge;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.api.*;

import java.util.List;
import java.util.Map;

/**
 * API implementation for AI Bridge.
 *
 * Endpoints:
 * - /JSON/aibridge/view/payloads/ - Get payloads by category
 * - /JSON/aibridge/view/fuzzerFiles/ - List available fuzzer files
 * - /JSON/aibridge/action/reportFinding/ - Report an AI finding as alert
 * - /JSON/aibridge/view/stats/ - Get bridge statistics
 */
public class AIBridgeAPI extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(AIBridgeAPI.class);
    private static final String PREFIX = "aibridge";

    private static final String VIEW_PAYLOADS = "payloads";
    private static final String VIEW_FUZZER_FILES = "fuzzerFiles";
    private static final String VIEW_STATS = "stats";

    private static final String ACTION_REPORT_FINDING = "reportFinding";

    private static final String PARAM_CATEGORY = "category";
    private static final String PARAM_LIMIT = "limit";
    private static final String PARAM_URL = "url";
    private static final String PARAM_NAME = "name";
    private static final String PARAM_RISK = "risk";
    private static final String PARAM_CONFIDENCE = "confidence";
    private static final String PARAM_DESCRIPTION = "description";
    private static final String PARAM_PARAM = "param";
    private static final String PARAM_ATTACK = "attack";
    private static final String PARAM_EVIDENCE = "evidence";
    private static final String PARAM_CWEID = "cweid";

    private final ExtensionAIBridge extension;
    private final Gson gson;

    private int requestCount = 0;
    private int findingsReported = 0;

    public AIBridgeAPI(ExtensionAIBridge extension) {
        this.extension = extension;
        this.gson = new Gson();

        // Register view endpoints
        this.addApiView(new ApiView(VIEW_PAYLOADS,
            new String[]{PARAM_CATEGORY},
            new String[]{PARAM_LIMIT}));
        this.addApiView(new ApiView(VIEW_FUZZER_FILES));
        this.addApiView(new ApiView(VIEW_STATS));

        // Register action endpoints
        this.addApiAction(new ApiAction(ACTION_REPORT_FINDING,
            new String[]{PARAM_URL, PARAM_NAME, PARAM_RISK, PARAM_CONFIDENCE, PARAM_DESCRIPTION},
            new String[]{PARAM_PARAM, PARAM_ATTACK, PARAM_EVIDENCE, PARAM_CWEID}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        requestCount++;

        switch (name) {
            case VIEW_PAYLOADS:
                return handlePayloadsView(params);

            case VIEW_FUZZER_FILES:
                return handleFuzzerFilesView();

            case VIEW_STATS:
                return handleStatsView();

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        requestCount++;

        if (ACTION_REPORT_FINDING.equals(name)) {
            return handleReportFinding(params);
        }

        throw new ApiException(ApiException.Type.BAD_ACTION);
    }

    private ApiResponse handlePayloadsView(JSONObject params) throws ApiException {
        String category = params.getString(PARAM_CATEGORY);
        int limit = params.optInt(PARAM_LIMIT, 100);

        List<String> payloads = extension.getPayloadProvider()
            .getPayloads(category, limit);

        JsonObject response = new JsonObject();
        JsonArray payloadArray = new JsonArray();

        for (String payload : payloads) {
            payloadArray.add(payload);
        }

        response.add("payloads", payloadArray);
        response.addProperty("count", payloads.size());
        response.addProperty("category", category);

        return new ApiResponseElement("result", gson.toJson(response));
    }

    private ApiResponse handleFuzzerFilesView() {
        List<String> files = extension.getPayloadProvider().getAvailableFuzzerFiles();

        JsonObject response = new JsonObject();
        JsonArray fileArray = new JsonArray();

        for (String file : files) {
            fileArray.add(file);
        }

        response.add("files", fileArray);
        response.addProperty("count", files.size());

        return new ApiResponseElement("result", gson.toJson(response));
    }

    private ApiResponse handleStatsView() {
        JsonObject stats = new JsonObject();
        stats.addProperty("requests", requestCount);
        stats.addProperty("findingsReported", findingsReported);
        stats.addProperty("payloadCategories",
            extension.getPayloadProvider().getCategoryCount());

        return new ApiResponseElement("result", gson.toJson(stats));
    }

    private ApiResponse handleReportFinding(JSONObject params) throws ApiException {
        String url = params.getString(PARAM_URL);
        String name = params.getString(PARAM_NAME);
        int risk = params.getInt(PARAM_RISK);
        int confidence = params.getInt(PARAM_CONFIDENCE);
        String description = params.getString(PARAM_DESCRIPTION);

        // Optional parameters
        String param = params.optString(PARAM_PARAM, "");
        String attack = params.optString(PARAM_ATTACK, "");
        String evidence = params.optString(PARAM_EVIDENCE, "");
        int cweid = params.optInt(PARAM_CWEID, 0);

        try {
            extension.getAlertBridge().createAlert(
                url, name, risk, confidence, description,
                param, attack, evidence, cweid
            );

            findingsReported++;

            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.addProperty("message", "Alert created");

            return new ApiResponseElement("result", gson.toJson(response));

        } catch (Exception e) {
            LOGGER.error("Failed to create alert", e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
        }
    }
}
