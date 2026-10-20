package com.phishguard.ml;

import org.junit.jupiter.api.Test;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FeatureExtractorTest {

    private final FeatureExtractor extractor = new FeatureExtractor();

    @Test
    void extract_legitimateUrl_returnsSafeFeatures() {
        Map<String, Integer> features = extractor.extract("https://www.google.com");

        assertEquals(-1, features.get("having_IP_Address"));
        assertEquals(-1, features.get("having_At_Symbol"));
        assertEquals(-1, features.get("Shortining_Service"));
        assertEquals(-1, features.get("SSLfinal_State"));
        assertEquals(-1, features.get("having_Suspicious_Keyword"));
    }

    @Test
    void extract_ipAddressUrl_flagsIpFeature() {
        Map<String, Integer> features = extractor.extract("http://192.168.1.1/login");

        assertEquals(1, features.get("having_IP_Address"));
    }

    @Test
    void extract_atSymbolUrl_flagsAtFeature() {
        Map<String, Integer> features = extractor.extract("http://user@paypal.com");

        assertEquals(1, features.get("having_At_Symbol"));
    }

    @Test
    void extract_shortenerUrl_flagsShortener() {
        Map<String, Integer> features = extractor.extract("http://bit.ly/secure-login");

        assertEquals(1, features.get("Shortining_Service"));
    }

    @Test
    void extract_suspiciousKeyword_flagsKeyword() {
        Map<String, Integer> features = extractor.extract("https://example.com/verify-account-password");

        assertEquals(1, features.get("having_Suspicious_Keyword"));
    }

    @Test
    void extract_httpsUrl_sslSafe() {
        Map<String, Integer> features = extractor.extract("https://secure.example.com");

        assertEquals(-1, features.get("SSLfinal_State"));
    }

    @Test
    void extract_httpUrl_sslSuspicious() {
        Map<String, Integer> features = extractor.extract("http://insecure.example.com");

        assertEquals(1, features.get("SSLfinal_State"));
    }

    @Test
    void extract_subdomains_countsCorrectly() {
        Map<String, Integer> features = extractor.extract("https://a.b.c.example.com");

        // 3 subdomains -> 0 (suspicious)
        assertEquals(0, features.get("having_Sub_Domain"));
    }

    @Test
    void extract_manySubdomains_flagsPhishing() {
        Map<String, Integer> features = extractor.extract("https://a.b.c.d.e.example.com");

        // 5 subdomains -> 1 (phishing)
        assertEquals(1, features.get("having_Sub_Domain"));
    }

    @Test
    void extract_doubleSlashRedirect_flagsRedirect() {
        Map<String, Integer> features = extractor.extract("https://example.com//redirect");

        assertEquals(1, features.get("double_slash_redirect"));
    }

    @Test
    void extract_hyphenInDomain_flagsPrefixSuffix() {
        Map<String, Integer> features = extractor.extract("https://pay-pal.com");

        assertEquals(1, features.get("Prefix_Suffix"));
    }

    @Test
    void extract_malformedUrl_allSuspicious() {
        Map<String, Integer> features = extractor.extract("not-a-url");

        // All features should be 1 (suspicious) for malformed URLs
        for (Integer value : features.values()) {
            assertEquals(1, value);
        }
    }

    @Test
    void explain_returnsOnlySuspiciousFeatures() {
        Map<String, Integer> features = extractor.extract("http://192.168.1.1/@safe");
        Map<String, String> reasons = extractor.explain(features);

        assertTrue(reasons.containsKey("having_IP_Address"));
        assertTrue(reasons.containsKey("having_At_Symbol"));
        assertTrue(reasons.containsKey("SSLfinal_State"));
        assertFalse(reasons.containsKey("having_Suspicious_Keyword"));
    }

    @Test
    void featureNames_matchFeatureDefs() {
        Map<String, Integer> features = extractor.extract("https://example.com");

        assertEquals(FeatureDefs.FEATURE_NAMES.size(), features.size());
        for (String name : FeatureDefs.FEATURE_NAMES) {
            assertTrue(features.containsKey(name), "Missing feature: " + name);
        }
    }
}
