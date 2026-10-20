package com.phishguard.ml;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * FeatureExtractor
 *
 * Takes a raw URL string and extracts the phishing-related features defined in
 * {@link FeatureDefs}. The output is an ordered map whose keys match the ARFF
 * attribute names, and whose values follow the UCI dataset encoding:
 *
 *   -1 = legitimate / safe
 *    0 = suspicious / neutral
 *    1 = phishing / very suspicious
 *
 * This class contains NO Weka dependency so it can be unit-tested in isolation.
 */
public class FeatureExtractor {

    // Common URL shortening providers
    private static final Pattern SHORTENER = Pattern.compile(
            "(bit\\.ly|tinyurl\\.com|goo\\.gl|t\\.co|ow\\.ly|is\\.gd|buff\\.ly|cutt\\.ly|rebrand\\.ly|tiny\\.cc)",
            Pattern.CASE_INSENSITIVE);

    // Suspicious keywords often used in phishing pages
    private static final Pattern SUSPICIOUS_KEYWORD = Pattern.compile(
            "(login|signin|verify|secure|account|password|bank|update|confirm|paypal|ebay|wallet|credential)",
            Pattern.CASE_INSENSITIVE);

    // IPv4 pattern
    private static final Pattern IPV4 = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$");

    /**
     * Extract all features for the given URL.
     *
     * @param rawUrl the URL submitted by the user
     * @return ordered map of feature name -> encoded value
     */
    public Map<String, Integer> extract(String rawUrl) {
        String url = normalize(rawUrl);
        Map<String, Integer> features = new LinkedHashMap<>();

        URI uri;
        try {
            uri = new URI(url);
        } catch (Exception e) {
            // Malformed URL -> treat as highly suspicious
            return allSuspicious(url);
        }

        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        // A URI can be syntactically valid while still not being a usable web address.
        if (host.isBlank() || (!IPV4.matcher(host).matches() && !host.contains("."))) {
            return allSuspicious(url);
        }
        String path = uri.getPath() == null ? "" : uri.getPath();
        String query = uri.getQuery() == null ? "" : uri.getQuery();
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();

        // 1. having_IP_Address : 1 if host is an IP, else -1
        features.put("having_IP_Address", IPV4.matcher(host).matches() ? 1 : -1);

        // 2. URL_Length : -1 (<54), 0 (54-75), 1 (>75)
        int len = url.length();
        features.put("URL_Length", len < 54 ? -1 : (len <= 75 ? 0 : 1));

        // 3. Shortining_Service : 1 if a known shortener, else -1
        features.put("Shortining_Service", SHORTENER.matcher(host).find() ? 1 : -1);

        // 4. having_At_Symbol : 1 if '@' present, else -1
        features.put("having_At_Symbol", url.contains("@") ? 1 : -1);

        // 5. double_slash_redirect : 1 if "//" appears after the protocol, else -1
        int protoEnd = url.indexOf("://");
        String afterProto = protoEnd >= 0 ? url.substring(protoEnd + 3) : url;
        features.put("double_slash_redirect", afterProto.contains("//") ? 1 : -1);

        // 6. Prefix_Suffix : 1 if hyphen in domain, else -1
        features.put("Prefix_Suffix", host.contains("-") ? 1 : -1);

        // 7. having_Sub_Domain : -1 (0-2 subdomains = safe), 0 (3 = suspicious), 1 (4+ = phishing)
        int labels = host.isEmpty() ? 0 : host.split("\\.").length;
        int subdomains = Math.max(0, labels - 2);
        features.put("having_Sub_Domain", subdomains <= 2 ? -1 : (subdomains == 3 ? 0 : 1));

        // 8. SSLfinal_State : -1 (https), 0 (http w/ cert issues), 1 (no https)
        if ("https".equals(scheme)) {
            features.put("SSLfinal_State", -1);
        } else if ("http".equals(scheme)) {
            features.put("SSLfinal_State", 1);
        } else {
            features.put("SSLfinal_State", 0);
        }

        // 9. Domain_registeration_length : unknown -> 0 (neutral)
        features.put("Domain_registeration_length", 0);

        // 10. age_of_domain : unknown -> 0 (neutral)
        features.put("age_of_domain", 0);

        // 11. DNSRecord : assume present -> -1 (safe). Set 1 if host empty.
        features.put("DNSRecord", host.isEmpty() ? 1 : -1);

        // 12. web_traffic : unknown -> 0 (neutral)
        features.put("web_traffic", 0);

        // 13. URL_of_Anchor : offline mode does not scrape page HTML -> 0 (neutral)
        features.put("URL_of_Anchor", 0);

        // 14. Links_in_tags : offline mode does not scrape page HTML -> 0 (neutral)
        features.put("Links_in_tags", 0);

        // 15. having_Suspicious_Keyword : 1 if found, else -1
        features.put("having_Suspicious_Keyword",
                SUSPICIOUS_KEYWORD.matcher(url).find() ? 1 : -1);

        // 16. count_dot : total dots in URL (-1 <3, 0 =3-5, 1 >5)
        int dots = countChar(url, '.');
        features.put("count_dot", dots < 3 ? -1 : (dots <= 5 ? 0 : 1));

        // 17. count_hyphen : total hyphens in URL (-1 <2, 0 =2-3, 1 >3)
        int hyphens = countChar(url, '-');
        features.put("count_hyphen", hyphens < 2 ? -1 : (hyphens <= 3 ? 0 : 1));

        // 18. count_redirect : -1 (no // redirect), 1 (redirect present)
        features.put("count_redirect", features.get("double_slash_redirect"));

        return features;
    }

    /**
     * Human-readable forensic breakdown explaining why a URL was flagged.
     * Returns only the features that represent active threats or elevated warnings.
     */
    public Map<String, String> explain(Map<String, Integer> features) {
        Map<String, String> reasons = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> e : features.entrySet()) {
            String key = e.getKey();
            int val = e.getValue();
            // Skip unmeasured offline placeholder attributes
            if (val == 0 && isOfflinePlaceholder(key)) {
                continue;
            }
            if (val == 1 || (val == 0 && isElevatedWarning(key))) {
                reasons.put(key, describe(key, val));
            }
        }
        return reasons;
    }

    private boolean isOfflinePlaceholder(String name) {
        return "Domain_registeration_length".equals(name) ||
               "age_of_domain".equals(name) ||
               "web_traffic".equals(name) ||
               "Links_in_tags".equals(name) ||
               "URL_of_Anchor".equals(name);
    }

    private boolean isElevatedWarning(String name) {
        return "having_Sub_Domain".equals(name) ||
               "SSLfinal_State".equals(name);
    }

    private String describe(String name, int value) {
        switch (name) {
            case "having_IP_Address":
                return "Direct IPv4 Literal: Destination uses a raw numeric IP address instead of an authenticated domain name. Heavily correlated with evasive phishing infrastructure.";
            case "having_At_Symbol":
                return "Authority Credential Spoofing: Contains '@' delimiter in address. RFC 3986 causes web clients to ignore preceding text, redirecting victims to a hidden target.";
            case "double_slash_redirect":
                return "Path Redirection Anomaly: Detected embedded '//' inside URI path hierarchy, a common wrapper to bounce victims to rogue phishing kits.";
            case "Shortining_Service":
                return "URL Shortener Cloaking: Address is hosted on a public link shortener (e.g. bit.ly, tinyurl), concealing true destination reputation from perimeter scanners.";
            case "Prefix_Suffix":
                return "Domain Hyphenation / Typosquatting: Domain name incorporates hyphens (e.g., brand-security.com) frequently employed to forge counterfeit brand lookalikes.";
            case "having_Sub_Domain":
                return value == 1
                    ? "Deep Subdomain Stacking: Host contains 4+ subdomain tiers, circumventing public suffix boundary protections."
                    : "Elevated Subdomain Depth: Host contains 3 subdomain tiers, indicating multi-layer routing.";
            case "SSLfinal_State":
                return value == 1
                    ? "Unencrypted Insecure Scheme (HTTP): Traffic travels in plaintext with zero TLS encryption, exposing submitted credentials to interception."
                    : "Unverified Transport Security: Certificate state or protocol could not be independently authenticated.";
            case "having_Suspicious_Keyword":
                return "Phishing Lure Keywords: URI path or host includes high-risk credential keywords (e.g., 'login', 'verify', 'account', 'banking').";
            case "URL_Length":
                return value == 1
                    ? "Abnormal URI Length (>75 chars): Long addresses are deliberately structured to push malicious hostnames off-screen in mobile browsers."
                    : "Moderate URI Length (54-75 chars): Address length exceeds nominal web standards.";
            case "count_dot":
                return "High Dot Density: Abnormally high dot delimiter count indicates stacked subdomains or evasive routing.";
            case "count_hyphen":
                return "High Hyphen Density: Presence of multiple hyphens is strongly characteristic of spoofed domains.";
            case "count_redirect":
                return "Bounce Redirect Sequence: URL structure matches redirection bounce chains.";
            default:
                return value == 1 ? name + ": Critical Threat Anomaly Detected" : name + ": Elevated Suspicion Warning";
        }
    }

    private int countChar(String s, char c) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == c) count++;
        }
        return count;
    }

    private String normalize(String rawUrl) {
        if (rawUrl == null) return "";
        String u = rawUrl.trim();
        if (!u.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {
            u = "http://" + u;
        }
        return u;
    }

    private Map<String, Integer> allSuspicious(String url) {
        Map<String, Integer> f = new LinkedHashMap<>();
        for (String name : FeatureDefs.FEATURE_NAMES) {
            f.put(name, 1);
        }
        return f;
    }
}
