use bug_killer::types;

#[path = "../src/scanner/auth.rs"]
mod auth;

use auth::AuthSecurityScanner;
use bug_killer::types::Severity;
use std::path::Path;

// ===========================================================================
// Category 2: Authentication Rules (BK-AI-AUT-001 through BK-AI-AUT-012)
// ===========================================================================

#[test]
fn test_aut_001_protected_route_lacks_auth() {
    let vuln_snippet = r#"
const express = require('express');
const app = express();

// Vulnerable: Express route on /admin without middleware
app.get('/admin', (req, res) => {
    res.render('admin_panel');
});

// Vulnerable: Profile route without middleware
router.post('/account/delete', async (req, res) => {
    await deleteAccount(req.user);
});
"#;
    let path = Path::new("src/routes/admin.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Should detect 2 unprotected routes");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-001");
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].detector_id, "auth-security");

    let safe_snippet = r#"
app.get('/admin', requireAuth, (req, res) => {
    res.render('admin_panel');
});

router.post('/account/delete', [authenticateToken], async (req, res) => {
    await deleteAccount(req.user);
});

app.get('/public/catalog', (req, res) => {
    res.json({ public: true });
});
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Protected routes with middleware must not trigger findings"
    );
}

#[test]
fn test_aut_001_flask_protected_route() {
    let vuln_flask = r#"
@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('dashboard.html')
"#;
    let path = Path::new("views/admin.py");
    let findings = AuthSecurityScanner::scan_source(path, vuln_flask);
    assert_eq!(
        findings.len(),
        1,
        "Should detect Flask route lacking auth decorator"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-001");

    let safe_flask = r#"
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('dashboard.html')
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_flask);
    assert!(
        safe_findings.is_empty(),
        "Decorated Flask route must be clean"
    );
}

#[test]
fn test_aut_002_middleware_bypass_alternate_path() {
    let vuln_snippet = r#"
// Alternate path matrix punctuation bypass
const target = '/api/..;/admin';
if (req.url.endsWith('.json')) return next();
"#;
    let path = Path::new("middleware/auth.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Should detect path bypass patterns");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-AUT-002"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const canonicalPath = path.normalize(req.path);
if (canonicalPath.startsWith('/admin')) {
    enforceAuthentication(req, res, next);
}
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Normalized path check must be clean"
    );
}

#[test]
fn test_aut_003_is_authenticated_stub_mock() {
    let vuln_js = r#"
const isAuthenticated = () => true;
function checkAccess(req) {
    req.isAuthenticated = () => true;
}
"#;
    let path = Path::new("src/auth/guard.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_js);
    assert_eq!(
        findings.len(),
        2,
        "Should detect always-true auth stubs in JS"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-003");
    assert_eq!(findings[0].severity, Severity::High);

    let vuln_py = r#"
def is_authenticated(): return True
demoLogin = True
"#;
    let path_py = Path::new("auth/helpers.py");
    let findings_py = AuthSecurityScanner::scan_source(path_py, vuln_py);
    assert_eq!(
        findings_py.len(),
        2,
        "Should detect Python auth stub and demo login"
    );

    let safe_js = r#"
const isAuthenticated = (req) => {
    return Boolean(req.session && req.session.userId && !req.session.isExpired);
};
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_js);
    assert!(
        safe_findings.is_empty(),
        "Authentic session validation must not be flagged"
    );
}

#[test]
fn test_aut_004_plaintext_or_weak_password_hash() {
    let vuln_snippet = r#"
const crypto = require('crypto');

function storeCredentials(username, password) {
    const md5Hash = crypto.createHash('md5').update(password).digest('hex');
    user.password = req.body.password;
}

function legacyHasher(pwd) {
    return sha1(pwd);
}
"#;
    let path = Path::new("services/user.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Should detect md5, sha1, and plaintext password storage"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-AUT-004"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

async function storeCredentials(username, password) {
    const hash = await argon2.hash(password);
    await db.users.create({ username, passwordHash: hash });
}
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Argon2/bcrypt password hashing must not be flagged"
    );
}

#[test]
fn test_aut_005_guessable_reset_token() {
    let vuln_snippet = r#"
function generateRecovery(user) {
    const resetToken = Math.random().toString(36).substring(2);
    const resetCode = Math.floor(Math.random() * 1000000);
    return { resetToken, resetCode };
}
"#;
    let path = Path::new("auth/password_reset.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag Math.random() for reset token and code"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-005");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const crypto = require('crypto');

function generateRecovery(user) {
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetCode = crypto.randomInt(100000, 999999).toString();
    return { resetToken, resetCode };
}
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "CSPRNG reset token generation must be clean"
    );
}

#[test]
fn test_aut_006_email_phone_change_no_verification() {
    let vuln_snippet = r#"
app.post('/api/user/email', (req, res) => {
    user.email = req.body.email;
    user.save();
    res.json({ success: true });
});
"#;
    let path = Path::new("controllers/profile.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 1, "Should flag unverified email update");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-006");
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
app.post('/api/user/email', async (req, res) => {
    const isPasswordValid = await verifyPassword(req.user, req.body.currentPassword);
    if (!isPasswordValid) return res.status(401).json({ error: 'Re-authentication required' });
    const confirmationToken = generateVerificationToken(req.body.email);
    await sendConfirmationEmail(confirmationToken);
});
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Verified email update with password check must be clean"
    );
}

#[test]
fn test_aut_007_no_abuse_throttling_auth_routes() {
    let vuln_snippet = r#"
app.post('/login', (req, res) => {
    handleLogin(req, res);
});

router.post('/otp', async (req, res) => {
    verifyOtp(req, res);
});
"#;
    let path = Path::new("routes/auth.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag login and otp routes without rate limiter"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-007");
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
const otpLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 3 });

app.post('/login', loginLimiter, (req, res) => {
    handleLogin(req, res);
});

router.post('/otp', otpLimiter, async (req, res) => {
    verifyOtp(req, res);
});
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Rate-limited authentication routes must be clean"
    );
}

#[test]
fn test_aut_008_mfa_disabled_admin() {
    let vuln_snippet = r#"
const authConfig = {
    requireMfa: false,
    bypassMfa: true
};

if (user.isAdmin) {
    /* skip mfa */
    return next();
}
"#;
    let path = Path::new("config/auth.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Should flag disabled MFA flags and admin bypass"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-AUT-008"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const authConfig = {
    requireMfa: true,
    enforceMfa: true
};
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Enforced MFA configurations must not be flagged"
    );
}

#[test]
fn test_aut_009_fail_open_exception_handling() {
    let vuln_snippet = r#"
function authFilter(req, res, next) {
    try {
        verifyToken(req);
    } catch (err) {
        next();
    }
}
"#;
    let path = Path::new("middleware/authFilter.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Should flag catch next() fail-open pattern"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-009");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
function authFilter(req, res, next) {
    try {
        verifyToken(req);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
}
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Fail-closed exception handling must be clean"
    );
}

#[test]
fn test_aut_010_client_side_auth_only() {
    let vuln_snippet = r#"
if (localStorage.getItem('token')) {
    showAdminDashboard();
}

const isAdmin = Boolean(localStorage.getItem('isAdmin'));

// auth checked on client-side route guard alone
"#;
    let path = Path::new("frontend/guards.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 3, "Should flag client-side auth reliance");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-AUT-010"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
async function renderDashboard() {
    const res = await fetch('/api/user/session');
    if (res.ok) {
        const user = await res.json();
        mountApp(user);
    }
}
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Server-evaluated session access must be clean"
    );
}

#[test]
fn test_aut_011_jwt_decode_without_verify() {
    let vuln_snippet = r#"
const jwt = require('jsonwebtoken');

function getUserClaims(token) {
    const claims = jwt.decode(token);
    return claims;
}
"#;
    let path = Path::new("services/jwtHelper.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Should flag jwt.decode() usage without verify"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AUT-011");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const jwt = require('jsonwebtoken');

function getUserClaims(token) {
    const claims = jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
    return claims;
}
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "jwt.verify() must be clean");
}

#[test]
fn test_aut_012_oauth_missing_state() {
    let vuln_snippet = r#"
const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=123&redirect_uri=https://app.com/callback';
passport.authenticate('oauth2', { state: false });
"#;
    let path = Path::new("auth/oauth.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag missing OAuth state parameter"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-AUT-012"));
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=123&redirect_uri=https://app.com/callback&state=' + csrfState;
passport.authenticate('oauth2', { state: true });
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "OAuth URL with state parameter must be clean"
    );
}

// ===========================================================================
// Category 4: Sessions, Tokens, Cookies Rules (BK-AI-SES-001 through BK-AI-SES-012)
// ===========================================================================

#[test]
fn test_ses_001_weak_predictable_session_id() {
    let vuln_snippet = r#"
function newSession(user) {
    const sessionId = Math.random().toString(36).substring(2);
    const sid = Date.now().toString() + Math.random();
    return { sessionId, sid };
}
"#;
    let path = Path::new("session/manager.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Should flag non-crypto session IDs");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-001"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const crypto = require('crypto');

function newSession(user) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    return { sessionId };
}
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "CSPRNG session ID generation must be clean"
    );
}

#[test]
fn test_ses_002_session_fixation_not_rotated() {
    let vuln_snippet = r#"
app.post('/login', loginLimiter, async (req, res) => {
    const user = await authenticate(req.body);
    req.session.userId = user.id;
    req.session.save((err) => {
        res.redirect('/home');
    });
});
"#;
    let path = Path::new("controllers/auth.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Should flag unrotated session after login"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-SES-002");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
app.post('/login', loginLimiter, async (req, res) => {
    const user = await authenticate(req.body);
    req.session.regenerate((err) => {
        req.session.userId = user.id;
        req.session.save((err) => {
            res.redirect('/home');
        });
    });
});
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Regenerated session on login must be clean"
    );
}

#[test]
fn test_ses_003_logout_fails_to_invalidate_server_session() {
    let vuln_snippet = r#"
app.post('/logout', (req, res) => {
    res.clearCookie('session');
    res.redirect('/login');
});
"#;
    let path = Path::new("routes/logout.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Should flag logout with only cookie clearing"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-SES-003");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        res.clearCookie('session');
        res.redirect('/login');
    });
});
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Logout with server session destruction must be clean"
    );
}

#[test]
fn test_ses_004_cookie_lacks_secure() {
    let vuln_snippet = r#"
res.cookie('session', sid, { httpOnly: true, secure: false });
app.use(session({ cookie: { secure: false } }));
"#;
    let path = Path::new("server.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Should flag cookies with secure: false");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-004"));
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
res.cookie('session', sid, { httpOnly: true, secure: true, sameSite: 'strict' });
app.use(session({ cookie: { secure: true } }));
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Secure cookies must be clean");
}

#[test]
fn test_ses_005_cookie_lacks_httponly() {
    let vuln_snippet = r#"
res.cookie('token', jwt, { httpOnly: false, secure: true });
app.use(session({ cookie: { httpOnly: false } }));
"#;
    let path = Path::new("server.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag cookies with httpOnly: false"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-005"));
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
res.cookie('token', jwt, { httpOnly: true, secure: true });
app.use(session({ cookie: { httpOnly: true } }));
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "HttpOnly cookies must be clean");
}

#[test]
fn test_ses_006_samesite_defense_missing() {
    let vuln_snippet = r#"
res.cookie('sid', sid, { sameSite: 'None', secure: false });
const sessionConfig = { sameSite: false };
"#;
    let path = Path::new("app.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    let ses_006_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.cve.as_str() == "BK-AI-SES-006")
        .collect();
    assert_eq!(
        ses_006_findings.len(),
        2,
        "Should flag insecure SameSite cookie settings"
    );
    assert_eq!(ses_006_findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
res.cookie('sid', sid, { sameSite: 'Lax', secure: true });
const sessionConfig = { sameSite: 'Strict' };
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Proper SameSite attributes must be clean"
    );
}

#[test]
fn test_ses_007_token_lifetime_excessive() {
    let vuln_snippet = r#"
const token1 = jwt.sign(payload, secret, { expiresIn: '365d' });
const token2 = jwt.sign(payload, secret, { expiresIn: '10y' });
const options = { expiresIn: 'never' };
"#;
    let path = Path::new("auth/jwt.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 3, "Should flag overly long token lifetimes");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-007"));
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
const accessToken = jwt.sign(payload, secret, { expiresIn: '15m' });
const refreshToken = jwt.sign(payload, secret, { expiresIn: '7d' });
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Bounded token lifetimes must be clean"
    );
}

#[test]
fn test_ses_008_jwt_algorithm_confusion_or_none() {
    let vuln_snippet = r#"
const claims1 = jwt.verify(token, key, { algorithms: ['none', 'HS256'] });
const claims2 = jwt.verify(token, key, { algorithm: 'none' });
const claims3 = jwt.verify(token, pubkey, { algorithms: ['HS256', 'RS256'] });
"#;
    let path = Path::new("services/jwt.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Should flag none and algorithm confusion configurations"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-008"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const claims = jwt.verify(token, pubkey, { algorithms: ['RS256'] });
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Pinned asymmetric algorithm must be clean"
    );
}

#[test]
fn test_ses_009_token_logged_or_in_query() {
    let vuln_snippet = r#"
console.log('User auth_token:', authToken);
logger.info('Received token: ' + token);
res.redirect('/callback?access_token=' + accessToken);
"#;
    let path = Path::new("routes/auth.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Should flag logged tokens and URL embedding"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-009"));
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
res.json({ token: accessToken });
req.headers['authorization'] = `Bearer ${accessToken}`;
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Tokens passed in response body or headers must be clean"
    );
}

#[test]
fn test_ses_010_localstorage_holds_token() {
    let vuln_snippet = r#"
localStorage.setItem('auth_token', token);
sessionStorage.setItem('accessToken', jwt);
localStorage['jwt'] = userToken;
"#;
    let path = Path::new("frontend/storage.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Should flag Web Storage credential storage"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-010"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
localStorage.setItem('theme', 'dark');
sessionStorage.setItem('sidebar_collapsed', 'true');
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Non-credential UI state in localStorage must be clean"
    );
}

#[test]
fn test_ses_011_cookie_domain_path_scoping() {
    let vuln_snippet = r#"
res.cookie('sid', sid, { domain: '*', path: '/' });
res.cookie('sid', sid, { domain: '.example.com', path: '/' });
"#;
    let path = Path::new("server.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag broad wildcard/root domain cookies"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-011"));
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
res.cookie('sid', sid, { domain: 'app.example.com', path: '/api' });
res.cookie('sid', sid, { httpOnly: true, secure: true });
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Host-only or scoped domain cookies must be clean"
    );
}

#[test]
fn test_ses_012_refresh_token_reuse_permitted() {
    let vuln_snippet = r#"
const opts = { refreshTokenReuse: true };
rotate_refresh_token = False
// allow refresh token reuse
"#;
    let path = Path::new("config/jwt.js");
    let findings = AuthSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Should flag refresh token reuse permissions and comments"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-SES-012"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_snippet = r#"
const opts = {
    refreshTokenReuse: false,
    rotateRefreshToken: true
};
"#;
    let safe_findings = AuthSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Strict token rotation with no reuse must be clean"
    );
}
