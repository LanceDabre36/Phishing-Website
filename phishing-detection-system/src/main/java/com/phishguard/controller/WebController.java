package com.phishguard.controller;

import com.phishguard.ml.PredictionService;
import com.phishguard.model.ScanHistory;
import com.phishguard.model.User;
import com.phishguard.service.ScanService;
import com.phishguard.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Controller
public class WebController {

    private final ScanService scanService;
    private final UserService userService;
    private final PredictionService predictionService;

    public WebController(ScanService scanService,
                         UserService userService,
                         PredictionService predictionService) {
        this.scanService = scanService;
        this.userService = userService;
        this.predictionService = predictionService;
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/home";
    }

    @GetMapping("/home")
    public String home(Model model, HttpSession session) {
        User user = (User) session.getAttribute("user");
        model.addAttribute("user", user);
        model.addAttribute("scanResult", null);
        return "home";
    }

    @GetMapping("/scan")
    public String scanPage(@RequestParam(value = "url", required = false) String urlParam,
                           @RequestParam(value = "q", required = false) String qParam,
                           Model model,
                           HttpSession session) {
        String targetUrl = (urlParam != null && !urlParam.isBlank()) ? urlParam.trim()
                : ((qParam != null && !qParam.isBlank()) ? qParam.trim() : null);

        if (targetUrl != null) {
            return executeScan(targetUrl, session, model);
        }

        model.addAttribute("user", session.getAttribute("user"));
        return "scan";
    }

    @PostMapping("/scan")
    public String scan(@RequestParam("url") String url,
                       HttpSession session,
                       Model model) {
        return executeScan(url, session, model);
    }

    private String executeScan(String rawUrl, HttpSession session, Model model) {
        String cleanUrl = rawUrl != null ? rawUrl.trim() : "";
        if (cleanUrl.isEmpty()) {
            model.addAttribute("user", session.getAttribute("user"));
            return "scan";
        }

        PredictionService.PredictionResult result = predictionService.predict(cleanUrl);
        User user = (User) session.getAttribute("user");

        ScanHistory scan = null;
        if (user != null) {
            scan = scanService.saveResult(user.getId(), cleanUrl, result);
        }

        model.addAttribute("scanResult", result);
        model.addAttribute("scanRecord", scan);
        model.addAttribute("user", user);
        model.addAttribute("isGuest", user == null);
        return "result";
    }

    @GetMapping("/history")
    public String history(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        if (user == null) return "redirect:/login";

        List<ScanHistory> scans = scanService.findByUser(user.getId());
        model.addAttribute("scans", scans);
        model.addAttribute("user", user);
        return "history";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @PostMapping("/signup")
    public String signup(@RequestParam String username,
                         @RequestParam String email,
                         @RequestParam String password) {
        try {
            userService.register(username, email, password);
            return "redirect:/login?registered=true";
        } catch (IllegalArgumentException e) {
            return "redirect:/signup?error=" + e.getMessage();
        }
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/error/403")
    public String accessDenied() {
        return "error/403";
    }

    @GetMapping("/error/404")
    public String notFound() {
        return "error/404";
    }
}
