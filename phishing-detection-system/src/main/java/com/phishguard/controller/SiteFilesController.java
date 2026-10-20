package com.phishguard.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Generates crawl-control files from the configured public site address. */
@RestController
public class SiteFilesController {
    private final String baseUrl;

    public SiteFilesController(@Value("${site.base-url}") String baseUrl) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
    }

    @GetMapping(value = "/sitemap.xml", produces = MediaType.APPLICATION_XML_VALUE)
    public String sitemap() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n" +
                url("/home", "weekly", "1.0") + url("/scan", "monthly", "0.8") +
                "</urlset>";
    }

    @GetMapping(value = "/robots.txt", produces = MediaType.TEXT_PLAIN_VALUE)
    public String robots() {
        return "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api\nDisallow: /history\nDisallow: /login\nDisallow: /signup\n\nSitemap: " + baseUrl + "/sitemap.xml\n";
    }

    private String url(String path, String frequency, String priority) {
        return "  <url><loc>" + baseUrl + path + "</loc><changefreq>" + frequency + "</changefreq><priority>" + priority + "</priority></url>\n";
    }
}
