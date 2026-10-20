package com.phishguard.repository;

import com.phishguard.model.ScanHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {
    List<ScanHistory> findByUserIdOrderByScannedAtDesc(Long userId);

    long countByVerdict(String verdict);

    @Query("SELECT COUNT(s) FROM ScanHistory s WHERE s.userId = :userId AND s.verdict = :verdict")
    long countByUserIdAndVerdict(@Param("userId") Long userId, @Param("verdict") String verdict);

    @Query("SELECT COUNT(s) FROM ScanHistory s")
    long totalScans();

    @Query("SELECT COUNT(s) FROM ScanHistory s WHERE s.verdict = 'PHISHING'")
    long phishingScans();
}