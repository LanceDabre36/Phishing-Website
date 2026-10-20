package com.phishguard.ml;

import java.util.List;

/**
 * Central definition of the phishing features used by both the feature
 * extractor and the Weka model. The order of this list MUST match the
 * attribute order in the ARFF training file (see resources/dataset/training.arff).
 *
 * Each feature maps to a UCI "Phishing Websites" dataset attribute.
 * Values are encoded the same way as the original dataset:
 *   -1 = legitimate / safe, 0 = suspicious, 1 = phishing / very suspicious
 * (for binary-style features we use -1 / 1).
 */
public final class FeatureDefs {

    private FeatureDefs() {}

    /** Ordered list of feature attribute names (excluding the class label). */
    public static final List<String> FEATURE_NAMES = List.of(
            "having_IP_Address",      // URL uses an IP address instead of domain name
            "URL_Length",             // length of URL
            "Shortining_Service",     // url is shortened (bit.ly, tinyurl, ...)
            "having_At_Symbol",       // contains '@'
            "double_slash_redirect",  // // appearing in path (redirect hint)
            "Prefix_Suffix",          // hyphen '-' in domain
            "having_Sub_Domain",      // number of subdomains
            "SSLfinal_State",         // cert validity / HTTPS
            "Domain_registeration_length", // age of domain (years)
            "age_of_domain",          // domain age
            "DNSRecord",              // has DNS record
            "web_traffic",            // popularity / traffic
            "URL_of_Anchor",          // anchors to own domain
            "Links_in_tags",          // links in html tags
            "having_Suspicious_Keyword", // login/password/secure/account/etc.
            "count_dot",              // number of dots in URL
            "count_hyphen",           // number of hyphens in URL
            "count_redirect"          // number of redirects followed
    );

    /** The class attribute name used in the ARFF file. */
    public static final String CLASS_ATTRIBUTE = "Result";

    /** Possible class values. */
    public static final String[] CLASS_VALUES = {"legitimate", "phishing"};
}
