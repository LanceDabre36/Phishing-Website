package com.phishguard.model;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * ModelMetrics entity - stores the latest training evaluation results.
 */
@Entity
@Table(name = "model_metrics")
public class ModelMetrics {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, precision = 5, scale = 2)
    private BigDecimal accuracy;

    @Column(name = "precision_val", nullable = false, precision = 5, scale = 2)
    private BigDecimal precisionVal;

    @Column(nullable = false, precision = 5, scale = 2)
    private BigDecimal recall;

    @Column(name = "f1_score", nullable = false, precision = 5, scale = 2)
    private BigDecimal f1Score;

    @Column(name = "confusion_matrix", columnDefinition = "TEXT")
    private String confusionMatrix;

    @Column(name = "trained_at", updatable = false)
    private LocalDateTime trainedAt = LocalDateTime.now();

    public ModelMetrics() {}

    // getters & setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public BigDecimal getAccuracy() { return accuracy; }
    public void setAccuracy(BigDecimal accuracy) { this.accuracy = accuracy; }
    public BigDecimal getPrecisionVal() { return precisionVal; }
    public void setPrecisionVal(BigDecimal precisionVal) { this.precisionVal = precisionVal; }
    public BigDecimal getRecall() { return recall; }
    public void setRecall(BigDecimal recall) { this.recall = recall; }
    public BigDecimal getF1Score() { return f1Score; }
    public void setF1Score(BigDecimal f1Score) { this.f1Score = f1Score; }
    public String getConfusionMatrix() { return confusionMatrix; }
    public void setConfusionMatrix(String confusionMatrix) { this.confusionMatrix = confusionMatrix; }
    public LocalDateTime getTrainedAt() { return trainedAt; }
    public void setTrainedAt(LocalDateTime trainedAt) { this.trainedAt = trainedAt; }
}
