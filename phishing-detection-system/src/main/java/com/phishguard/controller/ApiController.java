package com.phishguard.controller;

import com.phishguard.ml.PredictionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * REST API endpoint for external clients / AJAX.
 * POST /api/scan  body: {"url": "http://..."}
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    private final PredictionService predictionService;

    public ApiController(PredictionService predictionService) {
        this.predictionService = predictionService;
    }

    @PostMapping("/scan")
    public ResponseEntity<Map<String, Object>> scan(@RequestBody Map<String, String> body) {
        String url = body.get("url");
        if (url == null || url.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing 'url'"));
        }
        PredictionService.PredictionResult r = predictionService.predict(url);
        Map<String, Object> response = new HashMap<>();
        response.put("url", url);
        response.put("verdict", r.verdict);
        response.put("confidence", r.confidence);
        response.put("features", r.features);
        response.put("reasons", r.reasons);
        return ResponseEntity.ok(response);
    }
}