package com.phishguard;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Guards against Thymeleaf parse failures in shared page fragments. */
@SpringBootTest
@AutoConfigureMockMvc
class WebPageRenderingTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void homePageRendersSharedLayoutAndMetadata() throws Exception {
        mockMvc.perform(get("/home"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Understand suspicious links")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("before you click")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("application/ld+json")));
    }

    @Test
    void unknownPublicPageUsesCustom404Template() throws Exception {
        mockMvc.perform(get("/a-page-that-does-not-exist"))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Page Not Found")));
    }

    @Test
    void scanPostRendersResultPage() throws Exception {
        com.phishguard.model.User user = new com.phishguard.model.User();
        user.setId(1L);
        user.setUsername("tester");
        user.setEmail("tester@example.com");
        user.setPasswordHash("x");
        user.setRole("USER");
        mockMvc.perform(post("/scan")
                        .with(user("tester").roles("USER"))
                        .sessionAttr("user", user)
                        .with(csrf())
                        .param("url", "https://www.google.com"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Scan Results")));
    }

    @Test
    void guestCanScanUrlWithoutAuthBarrier() throws Exception {
        mockMvc.perform(post("/scan")
                        .with(csrf())
                        .param("url", "https://www.google.com"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Scan Results")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Guest Mode")));
    }

    @Test
    void getScanWithQueryParamExecutesDirectScan() throws Exception {
        mockMvc.perform(get("/scan").param("q", "https://www.google.com"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Scan Results")));
    }

    @Test
    void suspiciousLinkRendersElevatedRiskVerdict() throws Exception {
        mockMvc.perform(post("/scan")
                        .with(csrf())
                        .param("url", "http://my-company-portal.net"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("SUSPICIOUS ANOMALY FLAGGED")));
    }
}
