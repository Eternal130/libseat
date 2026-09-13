// ============================================================================
// libseat - CSU Library Seat Reservation CLI
//
// Commands: reserve / list / cancel / seats
// Campus, floor and candidate seat list are CLI parameters.
//
// Build (MinGW-w64):
//   g++ -std=c++17 -O2 -o libseat.exe libseat.cpp -lwinhttp -lbcrypt -lcrypt32
//
// Area resolution chain (runtime, no hardcoded ids):
//   /v4/space/index  {}                       -> premises (campus) + storey map
//   /v4/space/pick   {premisesIds, storeyIds} -> areas of that campus/floor
//   /v4/Space/seat   {id: areaId, day}        -> seats
//   /v4/Space/map    {id: areaId}             -> day segments
//   /v4/space/confirm  encrypted              -> reserve
//   /v4/member/seat    /  /v4/space/cancel    -> list / cancel
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

// ----------------------------------------------------------------------------
// string helpers
// ----------------------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static bool starts_with(const std::string& h, const std::string& n) {
    return h.size() >= n.size() && h.compare(0, n.size(), n) == 0;
}

static bool contains(const std::string& h, const std::string& n) {
    return h.find(n) != std::string::npos;
}

static std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::string url_encode(const std::string& v) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(v.size() * 3);
    for (unsigned char c : v) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += (char)c;
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

// crude flat-JSON field extraction: string value of "key"
static std::optional<std::string> json_str(const std::string& j, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return std::nullopt;
    size_t c = j.find(':', p + pat.size());
    if (c == std::string::npos) return std::nullopt;
    size_t q = j.find('"', c + 1);
    if (q == std::string::npos) return std::nullopt;
    size_t q2 = j.find('"', q + 1);
    if (q2 == std::string::npos) return std::nullopt;
    return j.substr(q + 1, q2 - q - 1);
}

// raw field value (string or number)
static std::optional<std::string> json_val(const std::string& j, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return std::nullopt;
    size_t c = j.find(':', p + pat.size());
    if (c == std::string::npos) return std::nullopt;
    size_t s = c + 1;
    while (s < j.size() && (j[s] == ' ' || j[s] == '\t')) s++;
    if (s >= j.size()) return std::nullopt;
    if (j[s] == '"') {
        size_t q = j.find('"', s + 1);
        if (q == std::string::npos) return std::nullopt;
        return j.substr(s + 1, q - s - 1);
    }
    size_t e = s;
    while (e < j.size() && j[e] != ',' && j[e] != '}' && j[e] != ']' && j[e] != ' ') e++;
    return j.substr(s, e - s);
}

// objects inside the first array under "key": [ {...}, {...} ]
static std::vector<std::string> json_array_objs(const std::string& j, const std::string& key) {
    std::vector<std::string> out;
    std::string pat = "\"" + key + "\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return out;
    size_t b = j.find('[', p);
    if (b == std::string::npos) return out;
    int depth = 0;
    size_t obj_start = 0;
    for (size_t i = b; i < j.size(); i++) {
        char ch = j[i];
        if (ch == '{') {
            if (depth == 0) obj_start = i;
            depth++;
        } else if (ch == '}') {
            depth--;
            if (depth == 0) out.push_back(j.substr(obj_start, i - obj_start + 1));
        } else if (ch == ']' && depth == 0) {
            break;
        }
    }
    return out;
}

static std::string get_today_yyyymmdd() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    snprintf(buf, sizeof(buf), "%04d%02d%02d", st.wYear, st.wMonth, st.wDay);
    return buf;
}

static std::string get_date_ymd_dash(int offset_days) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    u.QuadPart += (ULONGLONG)offset_days * 864000000000ULL;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    FileTimeToSystemTime(&ft, &st);
    char buf[16];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    return buf;
}

static std::vector<std::string> split_seat_list(std::string s) {
    const std::string fwComma = "\xEF\xBC\x8C";  // UTF-8 full-width comma
    size_t p;
    while ((p = s.find(fwComma)) != std::string::npos) s.replace(p, 3, ",");
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',' || c == ';' || c == ' ') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// "3" -> "三楼"; anything else passed through
static std::string floor_param_to_name(const std::string& f) {
    if (f.size() == 1 && f[0] >= '1' && f[0] <= '9') {
        static const char* names[] = {"", "一楼", "二楼", "三楼", "四楼", "五楼", "六楼", "七楼", "八楼", "九楼"};
        return names[f[0] - '0'];
    }
    return f;
}

// ----------------------------------------------------------------------------
// Base64 (Crypt32)
// ----------------------------------------------------------------------------
static std::string base64_encode(const std::vector<unsigned char>& data) {
    DWORD need = 0;
    CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &need);
    std::string out(need, '\0');
    CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &need);
    out.resize(need);
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n')) out.pop_back();
    return out;
}

// ----------------------------------------------------------------------------
// AES-CBC-PKCS7 via BCrypt
// ----------------------------------------------------------------------------
static std::optional<std::vector<unsigned char>> aes_cbc(
    bool encrypt,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& data)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return std::nullopt;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           (ULONG)(sizeof(BCRYPT_CHAIN_MODE_CBC) - 1), 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return std::nullopt; }

    BCRYPT_KEY_HANDLE hkey = NULL;
    st = BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return std::nullopt; }

    std::vector<unsigned char> iv_copy = iv;
    std::vector<unsigned char> out;
    ULONG done = 0;

    if (encrypt) {
        size_t pad = 16 - (data.size() % 16);
        std::vector<unsigned char> padded = data;
        padded.insert(padded.end(), (unsigned char)pad, (unsigned char)pad);
        DWORD out_size = 0;
        BCryptEncrypt(hkey, (PUCHAR)padded.data(), (ULONG)padded.size(), NULL,
                      iv_copy.data(), (ULONG)iv_copy.size(), NULL, 0, &out_size, 0);
        out.resize(out_size);
        st = BCryptEncrypt(hkey, (PUCHAR)padded.data(), (ULONG)padded.size(), NULL,
                           iv_copy.data(), (ULONG)iv_copy.size(), out.data(), out_size, &done, 0);
    } else {
        if (data.empty() || data.size() % 16) { BCryptDestroyKey(hkey); BCryptCloseAlgorithmProvider(alg, 0); return std::nullopt; }
        DWORD out_size = 0;
        BCryptDecrypt(hkey, (PUCHAR)data.data(), (ULONG)data.size(), NULL,
                      iv_copy.data(), (ULONG)iv_copy.size(), NULL, 0, &out_size, 0);
        out.resize(out_size);
        st = BCryptDecrypt(hkey, (PUCHAR)data.data(), (ULONG)data.size(), NULL,
                           iv_copy.data(), (ULONG)iv_copy.size(), out.data(), out_size, &done, 0);
    }

    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(st)) return std::nullopt;
    out.resize(done);

    if (!encrypt && !out.empty()) {
        unsigned char pad = out.back();
        if (pad >= 1 && pad <= 16 && out.size() >= pad) out.resize(out.size() - pad);
    }
    return out;
}

static std::string cas_random_string(size_t n) {
    static const char chars[] = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";
    const size_t len = sizeof(chars) - 1;
    std::string out;
    HCRYPTPROV h = 0;
    if (!CryptAcquireContextA(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return "";
    for (size_t i = 0; i < n; i++) {
        unsigned char b;
        if (!CryptGenRandom(h, 1, &b)) { CryptReleaseContext(h, 0); return ""; }
        out += chars[b % len];
    }
    CryptReleaseContext(h, 0);
    return out;
}

// ----------------------------------------------------------------------------
// WinHTTP client with cookie jar + manual redirect control
// ----------------------------------------------------------------------------
struct HttpResponse {
    DWORD status = 0;
    std::string body;
    std::string location;
};

class HttpClient {
public:
    ~HttpClient() { if (hSession) WinHttpCloseHandle(hSession); }

    bool init() {
        hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        return hSession != NULL;
    }

    HttpResponse request(const std::string& method, const std::string& url,
                         const std::string& body = "", const std::string& contentType = "",
                         bool autoRedirect = true, int maxRedirects = 8,
                         const std::wstring& extraHeader = L"")
    {
        URL_COMPONENTS uc{};
        uc.dwStructSize = sizeof(uc);
        wchar_t host[256] = L"", path[2048] = L"";
        uc.lpszHostName = host; uc.dwHostNameLength = 255;
        uc.lpszUrlPath = path; uc.dwUrlPathLength = 2047;
        std::wstring wurl(url.begin(), url.end());
        if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) return err_response(0);

        bool is_https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
        INTERNET_PORT port = uc.nPort;

        HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
        if (!hConnect) return err_response(0);

        DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, std::wstring(method.begin(), method.end()).c_str(),
                                                path, NULL, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) { WinHttpCloseHandle(hConnect); return err_response(0); }

        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));

        std::wstring whost_str(host);
        std::string host_str(whost_str.begin(), whost_str.end());
        std::string cookie = cookie_header();
        if (!cookie.empty()) {
            std::wstring w(cookie.begin(), cookie.end());
            WinHttpAddRequestHeaders(hRequest, (L"Cookie: " + w).c_str(), (ULONG)-1, 0);
        }
        if (!contentType.empty()) {
            std::wstring w(contentType.begin(), contentType.end());
            WinHttpAddRequestHeaders(hRequest, (L"Content-Type: " + w).c_str(), (ULONG)-1, 0);
        }
        if (!extraHeader.empty()) {
            WinHttpAddRequestHeaders(hRequest, extraHeader.c_str(), (ULONG)-1, 0);
        }
        WinHttpAddRequestHeaders(hRequest, L"Accept: application/json, text/plain, */*", (ULONG)-1, 0);
        WinHttpAddRequestHeaders(hRequest, L"X-Requested-With: XMLHttpRequest", (ULONG)-1, 0);

        if (!autoRedirect) {
            DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));
        }

        BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     (LPVOID)(body.empty() ? NULL : (LPVOID)body.data()),
                                     (DWORD)body.size(), (DWORD)body.size(), 0);
        if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);

        HttpResponse res;
        if (!ok) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return err_response(GetLastError()); }

        DWORD status = 0, size = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
        res.status = status;

        for (DWORD idx = 0;; idx++) {
            wchar_t buf[4096]; DWORD blen = sizeof(buf) - 2;
            if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"Set-Cookie", buf, &blen, &idx)) break;
            if (GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND) break;
            std::string sc(buf, buf + wcslen(buf));
            store_cookie(sc);
        }
        {
            wchar_t buf[4096]; DWORD blen = sizeof(buf) - 2;
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"Location", buf, &blen, WINHTTP_NO_HEADER_INDEX)) {
                res.location = std::string(buf, buf + wcslen(buf));
            }
        }

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            std::vector<char> chunk(avail);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, chunk.data(), avail, &read)) break;
            if (read == 0) break;
            res.body.append(chunk.data(), read);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);

        if (autoRedirect && (status == 301 || status == 302 || status == 303 || status == 307 || status == 308)
            && !res.location.empty() && maxRedirects > 0) {
            std::string next = resolve_url(url, res.location);
            std::string nextMethod = (status == 307 || status == 308) ? method : "GET";
            return request(nextMethod, next, "", "", true, maxRedirects - 1);
        }
        return res;
    }

    std::map<std::string, std::string> cookies;

private:
    HINTERNET hSession = NULL;

    static HttpResponse err_response(DWORD code) {
        HttpResponse r;
        r.status = 0;
        char buf[64];
        snprintf(buf, sizeof(buf), "[winhttp error %lu]", (unsigned long)code);
        r.body = buf;
        return r;
    }

    void store_cookie(const std::string& setCookie) {
        size_t semi = setCookie.find(';');
        std::string pair = trim(semi == std::string::npos ? setCookie : setCookie.substr(0, semi));
        size_t eq = pair.find('=');
        if (eq == std::string::npos) return;
        std::string name = trim(pair.substr(0, eq));
        std::string value = trim(pair.substr(eq + 1));
        if (value == "deleted") return;
        cookies[name] = value;
    }

    std::string cookie_header() {
        std::string out;
        for (auto& kv : cookies) {
            if (!out.empty()) out += "; ";
            out += kv.first + "=" + kv.second;
        }
        return out;
    }

    static std::string resolve_url(const std::string& base, const std::string& loc) {
        if (starts_with(loc, "http://") || starts_with(loc, "https://")) return loc;
        size_t scheme = base.find("://");
        size_t host_end = base.find('/', scheme + 3);
        std::string root = base.substr(0, host_end == std::string::npos ? base.size() : host_end);
        if (starts_with(loc, "/")) return root + loc;
        return root + "/" + loc;
    }
};

// ----------------------------------------------------------------------------
// Domain layer
// ----------------------------------------------------------------------------
static const char* CAS_HOST = "https://ca.csu.edu.cn";
static const char* LIB_HOST = "https://libzw.csu.edu.cn";
static const char* CAS_SERVICE = "https://libzw.csu.edu.cn/v4/login/cas";

struct AppError : std::runtime_error {
    explicit AppError(const std::string& m) : std::runtime_error(m) {}
};

// token cache under %LOCALAPPDATA%\libseat\token_<user>.txt
// avoids repeated CAS logins that trigger risk control
// cache file line 1 = libzw JWT (~100 min TTL), line 2 = CAS CASTGC cookie
// (14 days with rememberMe). The CASTGC lets us silently mint new JWTs
// without a password login, so routine runs never touch the login form.
struct CachedAuth {
    std::string jwt;
    std::string castgc;
};

static std::string token_cache_path(const std::string& user) {
    char* la = getenv("LOCALAPPDATA");
    std::string base = la ? la : ".";
    return base + "\\libseat\\token_" + user + ".txt";
}

static CachedAuth load_cached_auth(const std::string& user) {
    CachedAuth out;
    HANDLE h = CreateFileA(token_cache_path(user).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return out;
    char buf[8192];
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &read, NULL);
    CloseHandle(h);
    if (!ok) return out;
    std::string data(buf, buf + read);
    size_t nl = data.find('\n');
    out.jwt = trim(nl == std::string::npos ? data : data.substr(0, nl));
    if (nl != std::string::npos) out.castgc = trim(data.substr(nl + 1));
    return out;
}

static void save_cached_auth(const std::string& user, const std::string& jwt, const std::string& castgc) {
    std::string path = token_cache_path(user);
    std::string dir = path.substr(0, path.rfind('\\'));
    CreateDirectoryA(dir.c_str(), NULL);
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string data = jwt + "\n" + castgc;
    DWORD written = 0;
    WriteFile(h, data.data(), (DWORD)data.size(), &written, NULL);
    CloseHandle(h);
}

struct AreaInfo {
    std::string id;
    std::string name;   // nameMerge e.g. "杏林校区馆-三楼-医学馆三楼电子阅览室"
};

struct LibSession {
    HttpClient http;
    std::string token;

    std::string castgc;

    bool probe_token() {
        auto r = api("/v4/member/seat", "{\"type\":\"1\",\"page\":1,\"limit\":1}");
        auto code = json_val(r.body, "code");
        return r.status == 200 && code && *code == "0";
    }

    // three-tier login: JWT probe -> CASTGC silent mint -> password login.
    // password is only needed when there is no usable CASTGC (first run or
    // after 14 days), which keeps password logins - and the school's login
    // risk control - to a minimum.
    void ensure_login(const std::string& username, const std::string& password) {
        CachedAuth cache = load_cached_auth(username);

        if (!cache.jwt.empty()) {
            token = cache.jwt;
            if (probe_token()) {
                fprintf(stderr, "[+] using cached token\n");
                castgc = cache.castgc;
                return;
            }
            fprintf(stderr, "[*] cached token expired\n");
        }

        if (!cache.castgc.empty()) {
            fprintf(stderr, "[*] refreshing token via CAS sso cookie\n");
            castgc = cache.castgc;
            http.cookies.clear();
            http.cookies["CASTGC"] = cache.castgc;
            // feed only the CASTGC: a valid TGT gets a ticket redirect without
            // any form interaction; keeps our TGT independent of the browser's.
            if (sso_redirect_login()) {
                save_cached_auth(username, token, castgc);
                fprintf(stderr, "[+] token refreshed via sso cookie\n");
                return;
            }
            fprintf(stderr, "[*] sso cookie unusable\n");
        }

        if (password.empty())
            throw AppError("no usable cached credentials for " + username +
                           " and no -p given; run once with -p");
        login(username, password);
        save_cached_auth(username, token, castgc);
        fprintf(stderr, "[+] credentials cached to %s\n", token_cache_path(username).c_str());
    }

    void login(const std::string& username, const std::string& password) {
        std::string loginUrl = std::string(CAS_HOST) + "/authserver/login?service=" + url_encode(CAS_SERVICE);
        auto r = http.request("GET", loginUrl);
        if (r.status != 200) throw AppError("CAS login page failed: HTTP " + std::to_string(r.status));
        std::string html = r.body;

        auto salt = extract_input(html, "pwdEncryptSalt");
        auto execution = extract_input(html, "execution");
        if (!execution) throw AppError("cannot parse CAS form (execution)");

        // password: AES-128-CBC-PKCS7, key=salt, iv=random16, plain=rand64+password
        std::string plain = cas_random_string(64) + password;
        std::string saltKey = salt ? *salt : "";
        std::string iv = cas_random_string(16);
        auto enc = aes_cbc(true,
                           std::vector<unsigned char>(saltKey.begin(), saltKey.end()),
                           std::vector<unsigned char>(iv.begin(), iv.end()),
                           std::vector<unsigned char>(plain.begin(), plain.end()));
        if (!enc) throw AppError("AES encrypt failed");
        std::string encPwd = base64_encode(*enc);

        std::string form =
            "username=" + url_encode(username) +
            "&password=" + url_encode(encPwd) +
            "&captcha=" +
            "&_eventId=submit" +
            "&cllt=userNameLogin" +
            "&dllt=generalLogin" +
            "&lt=" + url_encode(extract_input(html, "lt").value_or("")) +
            "&execution=" + url_encode(*execution) +
            "&rememberMe=on";

        auto r2 = http.request("POST", loginUrl, form, "application/x-www-form-urlencoded", false);
        if (r2.status != 302 || r2.location.empty()) {
            std::string msg = "CAS login failed (HTTP " + std::to_string(r2.status) + ")";
            if (contains(r2.body, "password") || contains(r2.body, "Password")) msg += ": wrong username/password";
            else if (contains(r2.body, "captcha")) msg += ": captcha required";
            throw AppError(msg);
        }

        auto it = http.cookies.find("CASTGC");
        if (it != http.cookies.end()) castgc = it->second;

        if (!exchange_redirect(r2.location))
            throw AppError("no cas code in redirect chain");
    }

    // CAS already knows us (CASTGC): hitting the login url 302s straight to a
    // ticket - no form needed.
    bool sso_redirect_login() {
        std::string loginUrl = std::string(CAS_HOST) + "/authserver/login?service=" + url_encode(CAS_SERVICE);
        auto r = http.request("GET", loginUrl, "", "", false);
        if (r.status != 302 || r.location.empty() || !contains(r.location, "ticket="))
            return false;
        auto it = http.cookies.find("CASTGC");
        if (it != http.cookies.end() && !it->second.empty()) castgc = it->second;
        return exchange_redirect(r.location);
    }

    // walk the redirect chain to "#/cas/?cas=<temp code>" and swap it for a JWT
    bool exchange_redirect(std::string loc) {
        std::string casCode;
        for (int i = 0; i < 6 && !loc.empty(); i++) {
            std::string abs = starts_with(loc, "http") ? loc : std::string(CAS_HOST) + loc;
            size_t cp = abs.find("cas=");
            if (cp != std::string::npos && abs.find("ticket=") == std::string::npos) {
                size_t start = cp + 4;
                size_t end = abs.find('&', start);
                casCode = abs.substr(start, end == std::string::npos ? std::string::npos : end - start);
            }
            auto rr = http.request("GET", abs, "", "", false);
            if (rr.status >= 300 && rr.status < 400 && !rr.location.empty()) { loc = rr.location; continue; }
            break;
        }
        if (casCode.empty()) return false;

        auto r3 = http.request("POST", std::string(LIB_HOST) + "/v4/login/user",
                               "{\"cas\":\"" + casCode + "\"}", "application/json");
        auto tok = json_str(r3.body, "token");
        if (r3.status != 200 || !tok || tok->empty() || *tok == "null")
            return false;
        token = *tok;
        return true;
    }

    HttpResponse api(const std::string& path, const std::string& jsonBody) {
        std::wstring auth = L"Authorization: bearer" + std::wstring(token.begin(), token.end());
        return http.request("POST", std::string(LIB_HOST) + path, jsonBody, "application/json", true, 8, auth);
    }

    // isCrypto variant: AES key = serverDate + reverse(serverDate), iv fixed
    HttpResponse api_crypto(const std::string& path, const std::string& jsonBody) {
        std::string day = get_today_yyyymmdd();
        std::string rev(day.rbegin(), day.rend());
        std::string key = day + rev;
        const std::string iv = "ZZWBKJ_ZHIHUAWEI";
        auto enc = aes_cbc(true,
                           std::vector<unsigned char>(key.begin(), key.end()),
                           std::vector<unsigned char>(iv.begin(), iv.end()),
                           std::vector<unsigned char>(jsonBody.begin(), jsonBody.end()));
        if (!enc) throw AppError("aes encrypt failed for " + path);
        return api(path, "{\"aesjson\":\"" + base64_encode(*enc) + "\"}");
    }

    // ---- area resolution: campus (name substring or premises id) [+ floor] -> areas ----
    std::string resolve_premises_id(const std::string& campus) {
        auto r = api("/v4/space/index", "{}");
        if (r.status != 200) throw AppError("space/index failed: HTTP " + std::to_string(r.status));
        for (auto& p : json_array_objs(r.body, "premises")) {
            std::string id = json_val(p, "id").value_or("");
            std::string name = json_val(p, "name").value_or("");
            if (campus == id || contains(name, campus)) return id;
        }
        std::string avail;
        for (auto& p : json_array_objs(r.body, "premises"))
            avail += json_val(p, "name").value_or("?") + " (id " + json_val(p, "id").value_or("?") + "), ";
        throw AppError("campus not found: \"" + campus + "\". available: " + avail);
    }

    std::vector<std::string> resolve_storey_ids(const std::string& premisesId, const std::string& floorName) {
        auto r = api("/v4/space/index", "{}");
        std::vector<std::string> out;
        for (auto& grp : json_array_objs(r.body, "storey")) {
            std::string gname = json_val(grp, "name").value_or("");
            if (!floorName.empty() && !contains(gname, floorName)) continue;
            for (auto& item : json_array_objs(grp, "list")) {
                if (json_val(item, "parentId").value_or("") == premisesId)
                    out.push_back(json_val(item, "id").value_or(""));
            }
        }
        return out;
    }

    std::vector<AreaInfo> resolve_areas(const std::string& premisesId,
                                        const std::vector<std::string>& storeyIds,
                                        const std::string& day) {
        std::string ids;
        for (auto& s : storeyIds) ids += (ids.empty() ? "\"" : ",\"") + s + "\"";
        std::string body = "{\"premisesIds\":\"" + premisesId + "\",\"categoryIds\":[],\"storeyIds\":[" +
                           ids + "],\"boutiqueIds\":[],\"date\":\"" + day + "\"}";
        auto r = api("/v4/space/pick", body);
        if (r.status != 200) throw AppError("space/pick failed: HTTP " + std::to_string(r.status));
        std::vector<AreaInfo> out;
        for (auto& a : json_array_objs(r.body, "area")) {
            AreaInfo ai;
            ai.id = json_val(a, "id").value_or("");
            ai.name = json_val(a, "nameMerge").value_or("");
            if (!ai.id.empty()) out.push_back(ai);
        }
        return out;
    }

    // ---- per-area operations ----
    struct SeatInfo {
        std::string id;
        std::string no;
        std::string status;   // 1=free 2=taken
    };

    std::vector<SeatInfo> list_seats(const std::string& areaId, const std::string& day) {
        std::string body = "{\"id\":\"" + areaId + "\",\"day\":\"" + day +
                           "\",\"label_id\":[],\"start_time\":\"07:30\",\"end_time\":\"22:00\",\"begdate\":\"\",\"enddate\":\"\"}";
        auto r = api("/v4/Space/seat", body);
        if (r.status != 200) throw AppError("Space/seat failed: HTTP " + std::to_string(r.status));
        std::vector<SeatInfo> out;
        for (auto& obj : json_array_objs(r.body, "list")) {
            SeatInfo si;
            si.id = json_val(obj, "id").value_or("");
            si.no = json_val(obj, "no").value_or("");
            si.status = json_val(obj, "status").value_or("");
            if (!si.no.empty()) out.push_back(si);
        }
        return out;
    }

    std::string area_segment(const std::string& areaId, const std::string& day) {
        auto r = api("/v4/Space/map", "{\"id\":\"" + areaId + "\"}");
        if (r.status != 200) throw AppError("Space/map failed: HTTP " + std::to_string(r.status));
        size_t p = r.body.find("\"day\":\"" + day + "\"");
        if (p == std::string::npos) throw AppError("day " + day + " not open for reservation");
        size_t times = r.body.find("\"times\":[", p);
        if (times == std::string::npos) throw AppError("no times segment for day");
        auto idv = json_val(r.body.substr(times, 300), "id");
        if (!idv) throw AppError("no segment id");
        return *idv;
    }

    struct Booking {
        std::string id;
        std::string status;      // 2=booked 3=in-use 4=ended 6=cancelled
        std::string statusName;
        std::string no;
        std::string area;
        std::string begin;
        std::string end;
    };

    std::vector<Booking> list_bookings() {
        auto r = api("/v4/member/seat", "{\"type\":\"1\",\"page\":1,\"limit\":10}");
        if (r.status != 200) throw AppError("member/seat failed: HTTP " + std::to_string(r.status));
        std::vector<Booking> out;
        for (auto& obj : json_array_objs(r.body, "data")) {
            Booking b;
            b.id = json_val(obj, "id").value_or("");
            b.status = json_val(obj, "status").value_or("");
            b.statusName = json_val(obj, "status_name").value_or("");
            b.no = json_val(obj, "no").value_or("");
            b.area = json_val(obj, "nameMerge").value_or("");
            b.begin = json_val(obj, "beginTime").value_or("");
            b.end = json_val(obj, "endTime").value_or("");
            if (!b.id.empty()) out.push_back(b);
        }
        return out;
    }

    std::string reserve_seat(const std::string& seatId, const std::string& day, const std::string& segment) {
        std::string plain = "{\"seat_id\":\"" + seatId + "\",\"segment\":\"" + segment +
                            "\",\"day\":\"" + day + "\",\"start_time\":\"\",\"end_time\":\"\"}";
        auto r = api_crypto("/v4/space/confirm", plain);
        auto code = json_val(r.body, "code");
        auto msg = json_str(r.body, "message");
        if (r.status != 200) throw AppError("confirm HTTP " + std::to_string(r.status));
        if (code && *code == "0") return "OK";
        return (msg ? *msg : "unknown error");
    }

    std::string cancel_booking(const std::string& bookId) {
        auto r = api("/v4/space/cancel", "{\"id\":\"" + bookId + "\"}");
        auto code = json_val(r.body, "code");
        auto msg = json_str(r.body, "message");
        if (r.status != 200) throw AppError("cancel HTTP " + std::to_string(r.status));
        if (code && *code == "0") return "OK";
        return (msg ? *msg : "unknown error");
    }

private:
    static std::optional<std::string> extract_input(const std::string& html, const std::string& name) {
        std::string pat = "name=\"" + name + "\"";
        size_t p = html.find(pat);
        if (p == std::string::npos) {
            pat = "id=\"" + name + "\"";
            p = html.find(pat);
            if (p == std::string::npos) return std::nullopt;
        }
        size_t vs = html.find("value=\"", p);
        if (vs == std::string::npos) return std::nullopt;
        size_t vq = html.find('"', vs + 7);
        if (vq == std::string::npos) return std::nullopt;
        return html.substr(vs + 7, vq - vs - 7);
    }
};

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------
static void print_usage() {
    fprintf(stderr,
        "libseat - CSU library seat reservation CLI\n\n"
        "Usage:\n"
        "  libseat reserve -u <id> -p <pwd> [-d 0|1] [-c campus] [-f floor] [-s seat list]\n"
        "      Reserve seats by priority list; stops at first success.\n"
        "  libseat list    -u <id> -p <pwd>\n"
        "      Show current & recent reservations.\n"
        "  libseat cancel  -u <id> -p <pwd> -i <booking id>\n"
        "  libseat seats   -u <id> -p <pwd> [-d 0|1] [-c campus] [-f floor] [-s seat list]\n"
        "      Show candidate seat statuses.\n\n"
        "Options:\n"
        "  -d 0|1        day offset: 0=today, 1=tomorrow (default 1)\n"
        "  -c campus     campus name substring or premises id\n"
        "                (e.g. -c 杏林 / -c 潇湘 / -c 岳麓山 / -c 71). Default: 杏林\n"
        "  -f floor      optional floor filter: digit or Chinese (e.g. -f 3 / -f 三楼)\n"
        "  -s seats      comma-separated candidate seats in priority order\n"
        "                (e.g. -s 3208,3209,3210). Default: 3208,3209,3210\n"
        "  -u / -p       student id / password. -p is optional once a token is\n"
        "                cached locally (%%LOCALAPPDATA%%\\libseat\\token_<id>.txt);\n"
        "                it is only used to refresh the token when expired.\n");
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) { print_usage(); return 2; }
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) args.push_back(wide_to_utf8(argv[i]));
    std::string cmd = wide_to_utf8(argv[1]);

    std::string user, pass, bookId;
    std::string campus = "杏林";
    std::string floor;
    std::string seatsParam = "3208,3209,3210";
    int dayOffset = 1;

    for (size_t i = 1; i < args.size(); i++) {
        std::string a = args[i];
        auto next = [&]() -> std::string { return (i + 1 < args.size()) ? args[++i] : ""; };
        if (a == "-u") user = next();
        else if (a == "-p") pass = next();
        else if (a == "-i") bookId = next();
        else if (a == "-d") dayOffset = atoi(next().c_str());
        else if (a == "-c") campus = next();
        else if (a == "-f") floor = next();
        else if (a == "-s") seatsParam = next();
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); print_usage(); return 2; }
    }
    if (user.empty()) { fprintf(stderr, "missing -u\n"); print_usage(); return 2; }
    if (dayOffset != 0 && dayOffset != 1) { fprintf(stderr, "-d must be 0 or 1\n"); return 2; }

    std::vector<std::string> wanted = split_seat_list(seatsParam);
    if (wanted.empty()) { fprintf(stderr, "empty seat list\n"); return 2; }

    std::string day = get_date_ymd_dash(dayOffset);

    LibSession sess;
    if (!sess.http.init()) { fprintf(stderr, "WinHTTP init failed\n"); return 1; }

    try {
        sess.ensure_login(user, pass);
    } catch (const AppError& e) {
        fprintf(stderr, "[-] %s\n", e.what());
        return 1;
    }

    if (cmd == "list") {
        try {
            auto books = sess.list_bookings();
            if (books.empty()) { printf("no reservations found.\n"); return 0; }
            printf("%-10s %-6s %-40s %-10s %s\n", "ID", "SEAT", "AREA", "STATUS", "TIME");
            for (auto& b : books)
                printf("%-10s %-6s %-40s %-10s %s ~ %s\n",
                       b.id.c_str(), b.no.c_str(), b.area.c_str(), b.statusName.c_str(),
                       b.begin.substr(0, 16).c_str(), b.end.substr(11, 5).c_str());
        } catch (const AppError& e) { fprintf(stderr, "[-] %s\n", e.what()); return 1; }
        return 0;
    }

    if (cmd == "cancel") {
        if (bookId.empty()) { fprintf(stderr, "cancel requires -i <booking id>\n"); return 2; }
        try {
            std::string res = sess.cancel_booking(bookId);
            if (res == "OK") { printf("[+] booking %s cancelled\n", bookId.c_str()); return 0; }
            printf("[-] cancel failed: %s\n", res.c_str());
            return 1;
        } catch (const AppError& e) { fprintf(stderr, "[-] %s\n", e.what()); return 1; }
    }

    if (cmd == "seats" || cmd == "reserve") {
        std::vector<AreaInfo> areas;
        try {
            std::string premisesId = sess.resolve_premises_id(campus);
            std::string floorName = floor.empty() ? std::string() : floor_param_to_name(floor);
            std::vector<std::string> storeyIds = sess.resolve_storey_ids(premisesId, floorName);
            if (storeyIds.empty())
                throw AppError("no storeys match campus id " + premisesId +
                               (floorName.empty() ? "" : " + floor " + floorName));
            areas = sess.resolve_areas(premisesId, storeyIds, day);
            if (areas.empty())
                throw AppError("no areas found for campus \"" + campus + "\"" +
                               (floorName.empty() ? "" : " floor " + floorName) + " on " + day);
            fprintf(stderr, "[*] campus=%s (id %s), %zu area(s), day=%s, seats=%s\n",
                    campus.c_str(), premisesId.c_str(), areas.size(), day.c_str(), seatsParam.c_str());
        } catch (const AppError& e) { fprintf(stderr, "[-] %s\n", e.what()); return 1; }

        // cache seat lists per area
        std::map<std::string, std::vector<LibSession::SeatInfo>> areaSeats;
        try {
            for (auto& a : areas) areaSeats[a.id] = sess.list_seats(a.id, day);
        } catch (const AppError& e) { fprintf(stderr, "[-] %s\n", e.what()); return 1; }

        auto find_seat = [&](const std::string& no) -> std::pair<const AreaInfo*, const LibSession::SeatInfo*> {
            for (auto& a : areas)
                for (auto& s : areaSeats[a.id])
                    if (s.no == no) return {&a, &s};
            return {nullptr, nullptr};
        };

        if (cmd == "seats") {
            printf("candidate seats for %s (campus %s):\n", day.c_str(), campus.c_str());
            for (auto& w : wanted) {
                auto [a, s] = find_seat(w);
                if (!a) { printf("  %s: NOT FOUND in any area of campus\n", w.c_str()); continue; }
                printf("  %-6s area=%s  seatId=%s  status=%s\n",
                       w.c_str(), a->name.c_str(), s->id.c_str(),
                       s->status == "1" ? "free" : (s->status == "2" ? "taken" : s->status.c_str()));
            }
            for (auto& a : areas) {
                int free = 0;
                for (auto& s : areaSeats[a.id]) if (s.status == "1") free++;
                printf("  area free/total: %s -> %d free\n", a.name.c_str(), free);
            }
            return 0;
        }

        // reserve
        for (auto& w : wanted) {
            auto [a, s] = find_seat(w);
            if (!a) { fprintf(stderr, "[!] seat %s not found in any area of campus\n", w.c_str()); continue; }
            fprintf(stderr, "[*] seat %s -> %s (seatId %s, status %s)\n",
                    w.c_str(), a->name.c_str(), s->id.c_str(),
                    s->status == "1" ? "free" : "taken");
            if (s->status != "1") { fprintf(stderr, "[!] seat %s not free, trying next\n", w.c_str()); continue; }
            try {
                std::string segment = sess.area_segment(a->id, day);
                std::string res = sess.reserve_seat(s->id, day, segment);
                if (res == "OK") {
                    printf("[+] reserved seat %s (%s) for %s\n", w.c_str(), a->name.c_str(), day.c_str());
                    return 0;
                }
                fprintf(stderr, "[-] seat %s reserve failed: %s\n", w.c_str(), res.c_str());
            } catch (const AppError& e) {
                fprintf(stderr, "[-] seat %s: %s\n", w.c_str(), e.what());
            }
        }
        fprintf(stderr, "[-] no candidate seat available; giving up\n");
        return 1;
    }

    print_usage();
    return 2;
}
