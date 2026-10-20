package com.phishguard.repository;

import com.phishguard.model.ModelMetrics;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface ModelMetricsRepository extends JpaRepository<ModelMetrics, Long> {
    Optional<ModelMetrics> findTopByOrderByTrainedAtDesc();
}