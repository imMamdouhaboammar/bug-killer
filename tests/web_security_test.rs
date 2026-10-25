#![allow(clippy::collapsible_if)]

pub use bug_killer::types;
use bug_killer::types::*;
use std::path::Path;

#[path = "../src/scanner/web.rs"]
mod web;

use web::WebSecurityScanner;

// ----------------------------------------------------------------------------
// Rule 1: BK-AI-WEB-001 (CWE-79) - DOM XSS
// ----------------------------------------------------------------------------

#[test]
fn test_web_001_dom_xss_detection() {
    let snippet = r#"
        function renderUser(userInput) {
            document.getElementById('profile').innerHTML = userInput;
            document.getElementById('badge').outerHTML = "<div class='" + userInput + "'></div>";
            document.write(location.search);
        }
    "#;
    let path = Path::new("frontend/src/views/UserView.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert!(
        findings.len() >= 3,
        "Expected at least 3 DOM XSS findings, got {}",
        findings.len()
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-001"));
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(findings.iter().all(|f| f.detector_id == "web-security"));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-79".to_string()))
    );
}

#[test]
fn test_web_001_dangerously_set_inner_html_detection() {
    let snippet = r#"
        export function ProfileCard({ userBio }) {
            return (
                <div
                    dangerouslySetInnerHTML={{
                        __html: userBio,
                    }}
                />
            );
        }
    "#;
    let path = Path::new("frontend/src/components/ProfileCard.tsx");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-WEB-001");
}

#[test]
fn test_web_001_dom_xss_clean() {
    let snippet = r#"
        function renderSafe(userInput) {
            document.getElementById('profile').textContent = userInput;
            document.getElementById('sanitized').innerHTML = DOMPurify.sanitize(userInput);
            element.innerHTML = "";
            element.innerHTML = "<div>Static safe content</div>";
        }
    "#;
    let path = Path::new("frontend/src/views/SafeView.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings for safe DOM operations, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 2: BK-AI-WEB-002 (CWE-79) - Server-Rendered Unescaped HTML
// ----------------------------------------------------------------------------

#[test]
fn test_web_002_server_rendered_xss_detection() {
    let snippet = r#"
        from flask import render_template_string
        from markupsafe import Markup

        @app.route('/greet')
        def greet():
            name = request.args.get('name')
            raw_html = Markup(f"<b>Hello {name}</b>")
            return render_template_string(f"<div>{name}</div>")
    "#;
    let path = Path::new("server/routes.py");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(
        findings.len(),
        2,
        "Expected 2 findings for Markup and render_template_string"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-002"));
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-79".to_string()))
    );
}

#[test]
fn test_web_002_blade_and_safe_filter_detection() {
    let snippet = r#"
        <div class="user-content">
            {!! $userBio !!}
            {{ blog_post | safe }}
        </div>
    "#;
    let path = Path::new("resources/views/profile.blade.php");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-002"));
}

#[test]
fn test_web_002_clean() {
    let snippet = r#"
        return render_template("user.html", name=name)
        <div class="user-content">
            {{ $userBio }}
            {{ blog_post }}
        </div>
    "#;
    let path = Path::new("server/templates/profile.html");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 3: BK-AI-WEB-003 (CWE-79) - Regex / Blacklist Sanitization
// ----------------------------------------------------------------------------

#[test]
fn test_web_003_regex_sanitization_detection() {
    let snippet = r#"
        function sanitizeInput(html) {
            let clean = html.replace(/<script.*?>.*?<\/script>/gi, '');
            let stripped = clean.replace(/<\/?script[^>]*>/gi, '');
            return stripped;
        }
    "#;
    let path = Path::new("src/utils/sanitizer.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-003"));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-79".to_string()))
    );
}

#[test]
fn test_web_003_clean() {
    let snippet = r#"
        import DOMPurify from 'dompurify';

        function sanitizeInput(html) {
            return DOMPurify.sanitize(html);
        }
        function formatWhitespace(text) {
            return text.replace(/\s+/g, ' ');
        }
    "#;
    let path = Path::new("src/utils/sanitizer.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 4: BK-AI-WEB-004 (CWE-601) - Client/Server Open Redirect
// ----------------------------------------------------------------------------

#[test]
fn test_web_004_open_redirect_detection() {
    let snippet = r#"
        // Client-side open redirect
        const urlParams = new URLSearchParams(window.location.search);
        const target = urlParams.get('next');
        window.location = target;

        // Express open redirect
        app.get('/redirect', (req, res) => {
            res.redirect(req.query.url);
        });
    "#;
    let path = Path::new("src/routes/auth.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-004"));
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-601".to_string()))
    );
}

#[test]
fn test_web_004_clean() {
    let snippet = r#"
        // Safe relative redirect
        window.location.href = '/dashboard';
        res.redirect('/login');
    "#;
    let path = Path::new("src/routes/auth.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 5: BK-AI-WEB-005 (CWE-346) - Missing postMessage Origin Validation
// ----------------------------------------------------------------------------

#[test]
fn test_web_005_postmessage_missing_origin_detection() {
    let snippet = r#"
        window.addEventListener('message', (e) => {
            const data = JSON.parse(e.data);
            handlePrivilegedAction(data);
        });
    "#;
    let path = Path::new("frontend/src/listener.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-WEB-005");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-346".to_string()));
}

#[test]
fn test_web_005_clean() {
    let snippet = r#"
        window.addEventListener('message', (e) => {
            if (e.origin !== 'https://trusted.app.space') {
                return;
            }
            const data = JSON.parse(e.data);
            handlePrivilegedAction(data);
        });
    "#;
    let path = Path::new("frontend/src/listener.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings for validated origin, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 6: BK-AI-WEB-006 (CWE-200) - Sensitive Data in Frontend Bundle
// ----------------------------------------------------------------------------

#[test]
fn test_web_006_frontend_secret_detection() {
    let snippet = r#"
        NEXT_PUBLIC_STRIPE_SECRET_KEY=example-placeholder
        REACT_APP_API_SECRET=super_secret_jwt_key
    "#;
    let path = Path::new(".env.production");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-006"));
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-200".to_string()))
    );
}

#[test]
fn test_web_006_clean() {
    let snippet = r#"
        NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_12345
        NEXT_PUBLIC_ANALYTICS_ID=UA-123456
        REACT_APP_API_URL=https://api.example.com
    "#;
    let path = Path::new(".env.production");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 7: BK-AI-WEB-007 (CWE-352) - CSRF-Sensitive Mutations in GET Routes
// ----------------------------------------------------------------------------

#[test]
fn test_web_007_csrf_get_mutation_detection() {
    let snippet = r#"
        app.get('/delete', (req, res) => {
            db.deleteUser(req.query.id);
            res.send('User deleted');
        });

        router.get('/user/update', (req, res) => {
            updateProfile(req.query);
        });
    "#;
    let path = Path::new("server/routes/users.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-007"));
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-352".to_string()))
    );
}

#[test]
fn test_web_007_clean() {
    let snippet = r#"
        app.post('/delete', csrfProtection, (req, res) => {
            db.deleteUser(req.body.id);
        });
        app.get('/users', (req, res) => {
            res.json(db.listUsers());
        });
    "#;
    let path = Path::new("server/routes/users.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 8: BK-AI-WEB-008 (CWE-693) - Over-Permissive or Disabled CSP
// ----------------------------------------------------------------------------

#[test]
fn test_web_008_overpermissive_csp_detection() {
    let snippet = r#"
        <meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval'">
        app.use(helmet({ contentSecurityPolicy: false }));
    "#;
    let path = Path::new("public/index.html");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-008"));
    assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-693".to_string()))
    );
}

#[test]
fn test_web_008_clean() {
    let snippet = r#"
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trustedcdn.com">
    "#;
    let path = Path::new("public/index.html");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 9: BK-AI-WEB-009 (CWE-829) - Third-Party JS Missing Integrity/SRI
// ----------------------------------------------------------------------------

#[test]
fn test_web_009_missing_sri_detection() {
    let snippet = r#"
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    "#;
    let path = Path::new("public/index.html");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-009"));
    assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-829".to_string()))
    );
}

#[test]
fn test_web_009_clean() {
    let snippet = r#"
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>
        <script src="/static/js/local-bundle.js"></script>
    "#;
    let path = Path::new("public/index.html");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 10: BK-AI-WEB-010 (CWE-1021) - Unsafe Iframe Embedding / Clickjacking
// ----------------------------------------------------------------------------

#[test]
fn test_web_010_clickjacking_framing_detection() {
    let snippet = r#"
        res.setHeader('X-Frame-Options', 'ALLOWALL');
        app.use(helmet({ frameguard: false }));
    "#;
    let path = Path::new("server/security.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-010"));
    assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-1021".to_string()))
    );
}

#[test]
fn test_web_010_clean() {
    let snippet = r#"
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
    "#;
    let path = Path::new("server/security.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 11: BK-AI-WEB-011 (CWE-942) - CORS Reflects Any Origin With Credentials
// ----------------------------------------------------------------------------

#[test]
fn test_web_011_cors_wildcard_credentials_detection() {
    let snippet = r#"
        app.use(cors({
            origin: true,
            credentials: true
        }));
    "#;
    let path = Path::new("server/app.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-WEB-011");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-942".to_string()));
}

#[test]
fn test_web_011_clean() {
    let snippet = r#"
        app.use(cors({
            origin: 'https://trusted.app.space',
            credentials: true
        }));
    "#;
    let path = Path::new("server/app.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 12: BK-AI-WEB-012 (CWE-532) - Credentials in Client Telemetry
// ----------------------------------------------------------------------------

#[test]
fn test_web_012_telemetry_credentials_detection() {
    let snippet = r#"
        Sentry.captureMessage("User auth failure with password: " + userPassword);
        mixpanel.track('login_attempt', { authToken: token });
    "#;
    let path = Path::new("frontend/src/auth.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-WEB-012"));
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(
        findings
            .iter()
            .all(|f| f.advisory_ids.contains(&"CWE-532".to_string()))
    );
}

#[test]
fn test_web_012_clean() {
    let snippet = r#"
        Sentry.captureException(err);
        mixpanel.track('login_attempt', { userId: user.id });
    "#;
    let path = Path::new("frontend/src/auth.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 13: BK-AI-WEB-013 (CWE-200) - Unprotected File Download URL Without Auth
// ----------------------------------------------------------------------------

#[test]
fn test_web_013_unprotected_download_detection() {
    let snippet = r#"
        app.get('/download/:fileId', (req, res) => {
            const filePath = getPath(req.params.fileId);
            res.download(filePath);
        });
    "#;
    let path = Path::new("server/controllers/files.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-WEB-013");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-200".to_string()));
}

#[test]
fn test_web_013_clean() {
    let snippet = r#"
        app.get('/download/:fileId', requireAuth, (req, res) => {
            res.download(getPath(req.params.fileId));
        });
    "#;
    let path = Path::new("server/controllers/files.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 14: BK-AI-WEB-014 (CWE-525) - Service Worker Caching Private Responses
// ----------------------------------------------------------------------------

#[test]
fn test_web_014_service_worker_private_cache_detection() {
    let snippet = r#"
        self.addEventListener('install', (event) => {
            event.waitUntil(
                caches.open('v1').then((cache) => {
                    return cache.addAll([
                        '/api/user/profile',
                        '/api/billing'
                    ]);
                })
            );
        });
    "#;
    let path = Path::new("public/sw.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-WEB-014");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-525".to_string()));
}

#[test]
fn test_web_014_clean() {
    let snippet = r#"
        self.addEventListener('install', (event) => {
            event.waitUntil(
                caches.open('v1').then((cache) => {
                    return cache.addAll([
                        '/static/css/main.css',
                        '/static/js/bundle.js',
                        '/offline.html'
                    ]);
                })
            );
        });
    "#;
    let path = Path::new("public/sw.js");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}

// ----------------------------------------------------------------------------
// Rule 15: BK-AI-WEB-015 (CWE-200) - SSR / Hydration State Leaking Sensitive State
// ----------------------------------------------------------------------------

#[test]
fn test_web_015_ssr_hydration_leak_detection() {
    let snippet = r#"
        window.__INITIAL_STATE__ = {
            user: currentUser,
            passwordHash: user.password_hash,
            apiKey: user.secret_api_key
        };
    "#;
    let path = Path::new("server/views/index.html");
    let findings = WebSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-WEB-015");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-200".to_string()));
}

#[test]
fn test_web_015_clean() {
    let snippet = r#"
        window.__INITIAL_STATE__ = {
            theme: 'dark',
            locale: 'en',
            user: {
                id: user.id,
                displayName: user.displayName
            }
        };
    "#;
    let path = Path::new("server/views/index.html");
    let findings = WebSecurityScanner::scan_source(path, snippet);
    assert!(
        findings.is_empty(),
        "Expected 0 findings, got {:?}",
        findings
    );
}
