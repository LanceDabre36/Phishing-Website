package com.phishguard.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/** Supplies consistent metadata to server-rendered pages. */
@ControllerAdvice
public class SiteMetadataAdvice {
    private final String siteBaseUrl;

    public SiteMetadataAdvice(@Value("${site.base-url}") String siteBaseUrl) {
        this.siteBaseUrl = siteBaseUrl.replaceAll("/+$", "");
    }

    @ModelAttribute("siteBaseUrl")
    public String siteBaseUrl() { return siteBaseUrl; }

    @ModelAttribute("requestPath")
    public String requestPath(HttpServletRequest request) { return request.getRequestURI(); }

    /** JSON-LD is supplied as already-serialized JSON to avoid JavaScript-inline parsing. */
    @ModelAttribute("siteSchemaJson")
    public String siteSchemaJson() {
        return "{\"@context\":\"https://schema.org\",\"@graph\":["
                + "{\"@type\":\"WebSite\",\"@id\":\"" + siteBaseUrl + "/#website\",\"url\":\"" + siteBaseUrl + "/\",\"name\":\"PhishGuard\",\"description\":\"Machine-learning-assisted phishing URL screening.\"},"
                + "{\"@type\":\"SoftwareApplication\",\"name\":\"PhishGuard\",\"url\":\"" + siteBaseUrl + "/\",\"applicationCategory\":\"SecurityApplication\",\"operatingSystem\":\"Web\",\"offers\":{\"@type\":\"Offer\",\"price\":\"0\",\"priceCurrency\":\"USD\"}},"
                + "{\"@type\":\"LocalBusiness\",\"name\":\"PhishGuard Security Lab\",\"url\":\"" + siteBaseUrl + "/\",\"areaServed\":\"Worldwide\",\"description\":\"Online phishing-awareness and URL screening service.\"}]}";
    }

    @ModelAttribute("authenticated")
    public boolean authenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }

    @ModelAttribute("admin")
    public boolean admin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authenticated() && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_ADMIN".equals(authority.getAuthority()));
    }
}
