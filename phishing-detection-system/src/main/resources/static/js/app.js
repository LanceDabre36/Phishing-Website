/* PhishGuard interactions: reveals, counters, scan overlay, result pipeline. */
(function () {
    'use strict';

    /* Human metadata for the 18 model signals. */
    var FEATURE_META = {
        having_IP_Address: { t: 'IP instead of domain', g: 'Address-bar signals', d: 'The host is a numeric IP address rather than a readable domain name.' },
        URL_Length: { t: 'URL length', g: 'Address-bar signals', d: 'Very long URLs are used to hide the real destination. Safe under 54 chars.' },
        Shortining_Service: { t: 'URL shortener', g: 'Address-bar signals', d: 'Shortened links (bit.ly, tinyurl) hide where you really land.' },
        having_At_Symbol: { t: '@ symbol', g: 'Address-bar signals', d: 'Browsers ignore everything before @, so attackers abuse it.' },
        double_slash_redirect: { t: '// redirect trick', g: 'Address-bar signals', d: 'A // appearing after the protocol hints at redirection.' },
        Prefix_Suffix: { t: 'Hyphen in domain', g: 'Address-bar signals', d: 'Legitimate domains rarely use hyphens as prefix/suffix.' },
        having_Sub_Domain: { t: 'Subdomain depth', g: 'Address-bar signals', d: 'Excessive subdomains mimic trusted sites.' },
        having_Suspicious_Keyword: { t: 'Suspicious keywords', g: 'Address-bar signals', d: 'Words like login, verify, secure, account or paypal in the URL.' },
        count_dot: { t: 'Dot count', g: 'Address-bar signals', d: 'Too many dots suggests stacked subdomains.' },
        count_hyphen: { t: 'Hyphen count', g: 'Address-bar signals', d: 'Too many hyphens is typical of look-alike domains.' },
        count_redirect: { t: 'Redirect count', g: 'Address-bar signals', d: 'Mirrors the double-slash redirect signal.' },
        SSLfinal_State: { t: 'HTTPS / certificate', g: 'Domain & encryption', d: 'HTTPS is expected; plain HTTP is flagged.' },
        Domain_registeration_length: { t: 'Registration length', g: 'Domain & encryption', d: 'Not checked live in this demo, kept neutral.' },
        age_of_domain: { t: 'Domain age', g: 'Domain & encryption', d: 'Not checked live in this demo, kept neutral.' },
        DNSRecord: { t: 'DNS record', g: 'Domain & encryption', d: 'Assumed present unless the host is empty.' },
        web_traffic: { t: 'Web traffic', g: 'Content & reputation', d: 'Popularity is not checked live, kept neutral.' },
        URL_of_Anchor: { t: 'Anchor structure', g: 'Content & reputation', d: 'Bare URLs with no path or query look anchor-like.' },
        Links_in_tags: { t: 'Links in tags', g: 'Content & reputation', d: 'Page content is not fetched, kept neutral.' }
    };
    var GROUPS = ['Address-bar signals', 'Domain & encryption', 'Content & reputation'];

    function onReady(fn) {
        if (document.readyState !== 'loading') fn();
        else document.addEventListener('DOMContentLoaded', fn);
    }

    onReady(function () {
        /* Mobile nav toggle */
        var toggle = document.querySelector('[data-nav-toggle]');
        var nav = document.getElementById('mainNav');
        if (toggle && nav) {
            toggle.addEventListener('click', function () {
                var expanded = toggle.getAttribute('aria-expanded') === 'true';
                toggle.setAttribute('aria-expanded', String(!expanded));
                nav.classList.toggle('show', !expanded);
            });
        }

        /* Scroll reveals */
        var revealEls = document.querySelectorAll('.reveal');
        if ('IntersectionObserver' in window && revealEls.length) {
            var io = new IntersectionObserver(function (entries) {
                entries.forEach(function (e) {
                    if (e.isIntersecting) { e.target.classList.add('revealed'); io.unobserve(e.target); }
                });
            }, { threshold: 0.12 });
            revealEls.forEach(function (el) { io.observe(el); });
        } else {
            revealEls.forEach(function (el) { el.classList.add('revealed'); });
        }

        /* Animated counters */
        var counters = document.querySelectorAll('[data-count]');
        if ('IntersectionObserver' in window && counters.length) {
            var cio = new IntersectionObserver(function (entries) {
                entries.forEach(function (e) {
                    if (e.isIntersecting) { animateCount(e.target); cio.unobserve(e.target); }
                });
            }, { threshold: 0.4 });
            counters.forEach(function (el) { cio.observe(el); });
        }
        function animateCount(el) {
            var target = parseFloat(el.getAttribute('data-count'));
            var decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
            var dur = 1400, start = null;
            function frame(ts) {
                if (!start) start = ts;
                var p = Math.min((ts - start) / dur, 1);
                var eased = 1 - Math.pow(1 - p, 3);
                el.textContent = (target * eased).toFixed(decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
                if (p < 1) requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }

        initScanPage();
        initResultPipeline();
    });

    /* ---------- Scan page: chips + progress overlay ---------- */
    function initScanPage() {
        var form = document.getElementById('scanForm');
        var input = document.getElementById('urlInput');
        var overlay = document.getElementById('scanOverlay');
        if (!form || !input) return;

        document.querySelectorAll('[data-sample]').forEach(function (chip) {
            chip.addEventListener('click', function () {
                input.value = chip.getAttribute('data-sample');
                input.focus();
            });
        });

        form.addEventListener('submit', function (event) {
            var raw = input.value.trim();
            var candidate = /^https?:\/\//i.test(raw) ? raw : 'https://' + raw;
            try {
                var parsed = new URL(candidate);
                if (!parsed.hostname || parsed.hostname.indexOf('.') < 0) throw new Error('bad host');
                input.value = candidate;
            } catch (err) {
                event.preventDefault();
                input.setCustomValidity('Enter a complete web address, such as https://example.com.');
                input.reportValidity();
                return;
            }
            if (overlay) {
                overlay.classList.add('show');
                var steps = overlay.querySelectorAll('.scan-step');
                steps.forEach(function (s, i) {
                    setTimeout(function () { s.classList.add('on'); }, 350 * (i + 1));
                });
            }
        });
        input.addEventListener('input', function () { input.setCustomValidity(''); });
    }

    /* ---------- Result page: 4-stage animated pipeline ---------- */
    function initResultPipeline() {
        var root = document.getElementById('pipeline');
        if (!root || !window.__SCAN__) return;
        var data = window.__SCAN__;
        var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        buildUrlStage(data);
        buildFeatureStage(data);
        buildModelStage(data);
        buildVerdictStage(data);

        var replay = document.getElementById('replayBtn');
        if (replay) replay.addEventListener('click', function () { runPipeline(true); });
        runPipeline(false);

        function setStep(idx) {
            var steps = root.querySelectorAll('.step');
            steps.forEach(function (s, i) {
                s.classList.toggle('active', i === idx);
                s.classList.toggle('done', i < idx);
            });
            root.querySelectorAll('.stage').forEach(function (st) {
                st.classList.toggle('show', st.getAttribute('data-stage') === String(idx));
            });
        }

        function runPipeline(replayMode) {
            var stages = [0, 1, 2, 3];
            if (reduced) {
                document.querySelectorAll('.feat-card').forEach(function (c) {
                    c.classList.add('in');
                    var fill = c.querySelector('.meter > span');
                    if (fill) fill.style.width = fill.getAttribute('data-w') + '%';
                });
                finishRing(true);
                document.getElementById('verdictBanner').classList.add('show');
                setStep(3);
                Array.prototype.forEach.call(root.querySelectorAll('.stage'), function (st) { st.classList.add('show'); });
                return;
            }
            /* reset */
            document.querySelectorAll('.feat-card').forEach(function (c) { c.classList.remove('in'); });
            document.getElementById('verdictBanner').classList.remove('show');
            resetRing();
            var t = 0;
            stages.forEach(function (s, k) {
                t += (k === 0 ? 200 : 2100);
                setTimeout(function () {
                    setStep(s);
                    if (s === 1) revealFeatures();
                    if (s === 2) finishRing(false);
                    if (s === 3) {
                        document.getElementById('verdictBanner').classList.add('show');
                        countUp();
                    }
                }, replayMode ? t * 0.6 : t);
            });
        }

        function revealFeatures() {
            var cards = document.querySelectorAll('.feat-card');
            cards.forEach(function (c, i) {
                setTimeout(function () {
                    c.classList.add('in');
                    var fill = c.querySelector('.meter > span');
                    if (fill) fill.style.width = fill.getAttribute('data-w') + '%';
                }, i * 90);
            });
        }
    }

    function esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    /* Stage 1: URL breakdown */
    function buildUrlStage(data) {
        var box = document.getElementById('urlBreakdown');
        if (!box) return;
        var raw = data.url || '';
        var norm = raw;
        if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) norm = 'http://' + raw;
        var parts = { protocol: '-', host: '-', path: '-', query: '-' };
        try {
            var u = new URL(norm);
            parts.protocol = u.protocol.replace(':', '') || '-';
            parts.host = u.hostname || '-';
            parts.path = u.pathname && u.pathname !== '/' ? u.pathname : '-';
            parts.query = u.search ? u.search.slice(1) : '-';
        } catch (e) { /* keep dashes */ }
        var dots = (raw.match(/\./g) || []).length;
        var hyphens = (raw.match(/-/g) || []).length;
        box.innerHTML =
            '<div class="mb-2"><span class="text-muted small fw-bold">SUBMITTED</span><br>' +
            '<span class="url-chip"><b>URL</b> ' + esc(raw) + '</span></div>' +
            '<div><span class="text-muted small fw-bold">PARSED</span><br>' +
            '<span class="url-chip"><b>protocol</b> ' + esc(parts.protocol) + '</span>' +
            '<span class="url-chip"><b>host</b> ' + esc(parts.host) + '</span>' +
            '<span class="url-chip"><b>path</b> ' + esc(parts.path) + '</span>' +
            '<span class="url-chip"><b>query</b> ' + esc(parts.query) + '</span></div>' +
            '<div class="mt-2"><span class="url-chip"><b>length</b> ' + raw.length + ' chars</span>' +
            '<span class="url-chip"><b>dots</b> ' + dots + '</span>' +
            '<span class="url-chip"><b>hyphens</b> ' + hyphens + '</span></div>';
    }

    /* Stage 2: grouped feature meters */
    function buildFeatureStage(data) {
        var wrap = document.getElementById('featureGroups');
        if (!wrap) return;
        var feats = data.features || {};
        var html = '';
        GROUPS.forEach(function (g) {
            var cards = '';
            Object.keys(feats).forEach(function (key) {
                var meta = FEATURE_META[key] || { t: key, g: g, d: '' };
                if (meta.g !== g) return;
                var v = feats[key];
                var cls = v >= 1 ? 'bad' : (v >= 0 ? 'neutral' : 'safe');
                var lbl = v >= 1 ? 'PHISHING' : (v >= 0 ? 'NEUTRAL' : 'SAFE');
                var w = v >= 1 ? 100 : (v >= 0 ? 55 : 12);
                cards += '<div class="col-md-6 mb-3"><div class="feat-card h-100">' +
                    '<div class="d-flex justify-content-between align-items-center gap-2">' +
                    '<span class="feat-name">' + esc(meta.t) + '</span>' +
                    '<span class="feat-val v-' + cls + '">' + lbl + ' ' + v + '</span></div>' +
                    '<div class="feat-desc">' + esc(meta.d) + '</div>' +
                    '<div class="meter ' + cls + '"><span data-w="' + w + '"></span></div>' +
                    '</div></div>';
            });
            if (cards) html += '<h3 class="h6 mt-4 mb-3 text-uppercase text-muted">' + esc(g) + '</h3><div class="row">' + cards + '</div>';
        });
        wrap.innerHTML = html;
    }

    /* Stage 3: confidence ring */
    function buildModelStage(data) {
        var num = document.getElementById('confNum');
        if (num) num.setAttribute('data-target', data.confidence);
        var sub = document.getElementById('modelSub');
        if (sub) sub.textContent = 'J48 decision tree · ' + data.verdict + ' probability';
        var wrap = document.getElementById('ringWrap');
        if (wrap) wrap.classList.add(data.verdict === 'PHISHING' ? 'ringWrap-bad' : 'ringWrap-ok');
    }
    function resetRing() {
        var bar = document.getElementById('ringBar');
        if (bar) bar.style.strokeDashoffset = '326.7';
        var num = document.getElementById('confNum');
        if (num) num.textContent = '0%';
    }
    function finishRing(instant) {
        var data = window.__SCAN__;
        var bar = document.getElementById('ringBar');
        var c = 2 * Math.PI * 52;
        var target = c * (1 - Math.min(Math.max(data.confidence, 0), 100) / 100);
        if (bar) {
            if (instant) { bar.style.transition = 'none'; bar.style.strokeDashoffset = target; }
            else { bar.style.strokeDashoffset = target; }
        }
    }
    function countUp() {
        var num = document.getElementById('confNum');
        if (!num) return;
        var target = parseFloat(num.getAttribute('data-target')) || 0;
        var dur = 1200, start = null;
        function frame(ts) {
            if (!start) start = ts;
            var p = Math.min((ts - start) / dur, 1);
            num.textContent = (target * (1 - Math.pow(1 - p, 3))).toFixed(2) + '%';
            if (p < 1) requestAnimationFrame(frame);
        }
        requestAnimationFrame(frame);
    }

    /* Stage 4: verdict + reasons (enhance server-rendered list in place) */
    function buildVerdictStage(data) {
        var banner = document.getElementById('verdictBanner');
        if (!banner) return;
        banner.classList.add(data.verdict === 'PHISHING' ? 'is-bad' : 'is-ok');
        var list = document.getElementById('reasonListServer');
        if (!list) return;
        Array.prototype.forEach.call(list.querySelectorAll('li[data-key]'), function (li) {
            var key = li.getAttribute('data-key');
            var meta = FEATURE_META[key];
            if (!meta) return;
            var span = li.querySelector('span');
            var original = span ? span.textContent : '';
            li.innerHTML = '<i class="bi bi-arrow-right-circle me-2 text-primary"></i><strong>' +
                esc(meta.t) + '</strong><span class="text-muted"> — ' + esc(original) + '</span>';
        });
    }
})();
