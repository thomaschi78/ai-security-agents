/*
 * Payload Provider
 * Exposes ZAP's fuzzdb payloads via API
 */
package org.zaproxy.addon.aibridge;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Provider for fuzzing payloads from ZAP's fuzzdb.
 *
 * Categories supported:
 * - sqli: SQL injection payloads
 * - xss: Cross-site scripting payloads
 * - cmdi: Command injection payloads
 * - lfi: Local file inclusion payloads
 * - xxe: XML external entity payloads
 * - ssti: Server-side template injection payloads
 */
public class PayloadProvider {

    private static final Logger LOGGER = LogManager.getLogger(PayloadProvider.class);

    private final Map<String, List<String>> payloadCache;
    private final Path fuzzerBasePath;

    // Category to file path mappings
    private static final Map<String, String> CATEGORY_PATHS = Map.of(
        "sqli", "fuzzers/fuzzdb/attack/sql-injection",
        "xss", "fuzzers/fuzzdb/attack/xss",
        "cmdi", "fuzzers/fuzzdb/attack/os-cmd-execution",
        "lfi", "fuzzers/fuzzdb/attack/lfi",
        "path_traversal", "fuzzers/fuzzdb/attack/path-traversal",
        "xxe", "fuzzers/fuzzdb/attack/xxe",
        "ssti", "fuzzers/fuzzdb/attack/template-injection"
    );

    public PayloadProvider() {
        this.payloadCache = new HashMap<>();
        this.fuzzerBasePath = Paths.get(Constant.getZapHome());
    }

    /**
     * Get payloads for a category.
     *
     * @param category Payload category (sqli, xss, cmdi, etc.)
     * @param limit Maximum number of payloads to return
     * @return List of payloads
     */
    public List<String> getPayloads(String category, int limit) {
        // Check cache first
        if (payloadCache.containsKey(category)) {
            List<String> cached = payloadCache.get(category);
            return cached.subList(0, Math.min(limit, cached.size()));
        }

        // Load from files
        List<String> payloads = loadPayloads(category);
        payloadCache.put(category, payloads);

        return payloads.subList(0, Math.min(limit, payloads.size()));
    }

    /**
     * Load payloads from files for a category.
     */
    private List<String> loadPayloads(String category) {
        String pathStr = CATEGORY_PATHS.get(category.toLowerCase());
        if (pathStr == null) {
            LOGGER.warn("Unknown payload category: {}", category);
            return Collections.emptyList();
        }

        Path categoryPath = fuzzerBasePath.resolve(pathStr);
        List<String> payloads = new ArrayList<>();

        if (!Files.exists(categoryPath)) {
            LOGGER.warn("Payload path does not exist: {}", categoryPath);
            return payloads;
        }

        try {
            if (Files.isDirectory(categoryPath)) {
                // Load all files in directory
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(categoryPath, "*.txt")) {
                    for (Path file : stream) {
                        payloads.addAll(loadFile(file));
                    }
                }
            } else if (Files.isRegularFile(categoryPath)) {
                payloads.addAll(loadFile(categoryPath));
            }
        } catch (IOException e) {
            LOGGER.error("Error loading payloads from {}", categoryPath, e);
        }

        LOGGER.info("Loaded {} payloads for category {}", payloads.size(), category);
        return payloads;
    }

    /**
     * Load payloads from a single file.
     */
    private List<String> loadFile(Path file) throws IOException {
        return Files.lines(file, StandardCharsets.UTF_8)
            .map(String::trim)
            .filter(line -> !line.isEmpty() && !line.startsWith("#"))
            .collect(Collectors.toList());
    }

    /**
     * Get list of available fuzzer files.
     */
    public List<String> getAvailableFuzzerFiles() {
        List<String> files = new ArrayList<>();
        Path fuzzersPath = fuzzerBasePath.resolve("fuzzers");

        if (!Files.exists(fuzzersPath)) {
            return files;
        }

        try {
            Files.walk(fuzzersPath)
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".txt"))
                .forEach(p -> files.add(fuzzersPath.relativize(p).toString()));
        } catch (IOException e) {
            LOGGER.error("Error listing fuzzer files", e);
        }

        return files;
    }

    /**
     * Get number of categories available.
     */
    public int getCategoryCount() {
        return CATEGORY_PATHS.size();
    }

    /**
     * Clear payload cache.
     */
    public void clearCache() {
        payloadCache.clear();
    }

    /**
     * Get all available categories.
     */
    public Set<String> getCategories() {
        return CATEGORY_PATHS.keySet();
    }
}
