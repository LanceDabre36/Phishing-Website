package com.phishguard.service;

import com.phishguard.ml.PredictionService;
import com.phishguard.model.ScanHistory;
import com.phishguard.repository.ScanHistoryRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Service
public class ScanService {

    private final ScanHistoryRepository scanHistoryRepository;
    private final PredictionService predictionService;

    public ScanService(ScanHistoryRepository scanHistoryRepository,
                       PredictionService predictionService) {
        this.scanHistoryRepository = scanHistoryRepository;
        this.predictionService = predictionService;
    }

    @Transactional
    public ScanHistory scanUrl(Long userId, String url) {
        PredictionService.PredictionResult result = predictionService.predict(url);
        return saveResult(userId, url, result);
    }

    @Transactional
    public ScanHistory saveResult(Long userId, String url, PredictionService.PredictionResult result) {
        ScanHistory scan = new ScanHistory();
        scan.setUserId(userId);
        scan.setUrl(url);
        scan.setVerdict(result.verdict);
        scan.setConfidence(BigDecimal.valueOf(result.confidence));
        scan.setFeaturesJson(toJson(result.features, result.reasons));

        return scanHistoryRepository.save(scan);
    }

    public List<ScanHistory> findByUser(Long userId) {
        return scanHistoryRepository.findByUserIdOrderByScannedAtDesc(userId);
    }

    private String toJson(Map<String, Integer> features, Map<String, String> reasons) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"features\":{");
        boolean first = true;
        for (Map.Entry<String, Integer> e : features.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(e.getKey()).append("\":").append(e.getValue());
            first = false;
        }
        sb.append("},\"reasons\":{");
        first = true;
        for (Map.Entry<String, String> e : reasons.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
            first = false;
        }
        sb.append("}}");
        return sb.toString();
    }
}
