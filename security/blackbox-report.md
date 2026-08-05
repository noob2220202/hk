# dw-04.com 블랙박스 보안 점검 리포트

- **대상(Target):** `https://www.dw-04.com/` (대왕 카지노)
- **점검 유형:** 블랙박스(외부 관찰) — 소스코드 미열람 상태
- **권한(Authorization):** 사이트 소유자/운영자 본인이 점검을 요청·승인 (self-owned)
- **원칙:** 비파괴(non-destructive)·저볼륨 요청만 사용. DoS/대량요청/브루트포스/데이터변조 미수행
- **작성일:** 2026-08-05
- **다음 단계:** 화이트박스(소스코드) 확보 후 각 항목의 실제 원인 확인 및 수정 가이드 제공

> 이 리포트는 "외부에서 관찰 가능한 표면"에 대한 것입니다. 아래 다수 항목은 **잠재 취약점 후보**이며,
> 실제 익스플로잇 가능 여부는 화이트박스 단계에서 코드로 확정합니다.

---

## 0. 환경 관련 유의사항 (관측 한계)

- 대상은 **Cloudflare** 뒤에 있으며, 비브라우저/봇 요청은 다수 `403`으로 차단됩니다. 따라서 `403`은 "파일 없음"이 아니라 "WAF 차단"일 수 있어, 파일 부재를 단정할 수 없습니다.
- 본 점검 실행 환경은 **송신 TLS를 프록시가 종단**하므로, 실제 서버 인증서/암호군(cipher suite)/TLS 버전을 이 환경에서 신뢰성 있게 판별할 수 없습니다. → **TLS 구성은 외부 도구(SSL Labs 등)로 별도 확인 필요.**

---

## 1. 기술 스택 지문 (Fingerprint)

| 항목 | 관측값 | 근거 |
|---|---|---|
| CDN/WAF | Cloudflare | `server: cloudflare`, `cf-ray`, `nel`/`report-to` |
| 백엔드 | **PHP** | `Set-Cookie: PHPSESSID=...` |
| 프론트 | jQuery 스택 | `jquery-1.11.3.min.js`, `jquery-migrate-1.2.1`, `jquery.tmpl`, bxSlider, waterwheelCarousel, sweetalert2 |
| 서드파티 | Tawk.to(라이브챗), Vimeo, cdnjs | `embed.tawk.to/636de426...`, `player.vimeo.com`, `cdnjs.cloudflare.com` |
| 아키텍처 | 다수 `*.php` 페이지 + AJAX(`/post/*.php`, `/ajax/*.php`) | HTML/JS 분석 |

---

## 2. 발견 사항 (Findings)

심각도는 CVSS 정성 기준(블랙박스 관측 기반 추정치)입니다. 확정은 화이트박스에서.

### 🔴 F-01 (High) 세션 쿠키 보안 플래그 누락
관측된 `Set-Cookie`:

```
Set-Cookie: PHPSESSID=9prlnbpaau8dgjs6nij8u6qt6f; path=/; domain=.dw-04.com
Set-Cookie: UUID=a35d3729...260805150937; expires=...(1년); path=/; domain=.dw-04.com
```

- `HttpOnly` **없음** → XSS 발생 시 `document.cookie`로 세션 탈취 가능.
- `Secure` **없음** → HTTPS 전용 강제 안 됨. (HTTP→HTTPS 301은 있으나 HSTS가 없어 첫 요청/다운그레이드 시 평문 노출 가능)
- `SameSite` **없음** → CSRF 방어 계층 하나가 비어 있음(브라우저 기본값에 의존).
- `domain=.dw-04.com` → 모든 서브도메인으로 쿠키 공유. 서브도메인 중 하나라도 XSS/장악되면 세션 노출 범위 확대.

**영향:** 세션 탈취·계정 도용(카지노 특성상 금전 직접 연결). **우선 수정 대상.**

### 🔴 F-02 (High, 잠재) 클라이언트가 서버 응답/속성을 `eval()` — 광범위한 코드실행 싱크
`/js/ajax_call.js` 전반이 `eval` 기반입니다.

```js
// 서버 응답 본문 d 를 그대로 코드로 평가
function callback_default(d){ ... eval("r=" + d) ... }
// 응답 필드 callback 을 문자열로 실행
else if (typeof r.callback == "string"){ try { eval(r.callback) } catch(e){} }
// HTML 속성값을 코드로 평가
eval("o=" + this.getAttribute("ajax"));
var p = this.getAttribute("ajax-precall"); eval("(function(event){"+p+"}).apply(n,[k])");
// 응답을 그대로 DOM 삽입
function callback_html(d){ ... $(s).html(d) }  // d = 서버 응답, 인코딩 없음
```

- 서버 응답이 **JSON.parse가 아니라 `eval`** 로 처리됩니다(응답 `content-type`도 `text/html`).
- 어떤 엔드포인트든 **사용자 입력이 응답에 반영(reflected)** 되거나 **저장 후 재출력(stored)** 되면, 그 지점이 곧 XSS/스크립트 실행이 됩니다.
- `r.move`/`r.replace`/`r.reload` 는 서버가 지정한 URL로 `location`을 바꿉니다 → **오픈 리다이렉트/피싱** 가능성(서버가 이 값을 어떻게 만드는지 확인 필요).
- HTML에 **inline `onclick=` 88개** + 속성기반 `ajax`/`ajax-precall` eval → 템플릿에 사용자 데이터가 속성으로 들어가면 즉시 XSS.

**화이트박스 확정 포인트:** 각 `.php`가 응답 JSON을 생성할 때 사용자 입력을 어떻게 escape 하는지, `ajax`/`ajax-precall` 속성이 동적으로 생성되는 화면이 있는지.

### 🟠 F-03 (Medium) HSTS 미설정
- HTTP는 `301`로 HTTPS 리다이렉트되지만 모든 응답에 `Strict-Transport-Security` **없음**.
- 최초 접속/중간자(SSL stripping) 시 평문 통신 위험. 쿠키에 `Secure`가 없어 위험 가중(F-01과 결합).

### 🟠 F-04 (Medium) 보안 헤더 부재 (실제 앱 200 응답 기준)
앱의 정상 `200` 응답에 다음이 **모두 없음**:

- `Content-Security-Policy` (없음) → XSS 완화 계층 부재. F-02와 결합 시 위험 큼.
- `X-Content-Type-Options: nosniff` (없음) → MIME 스니핑.
- `X-Frame-Options` / `frame-ancestors` (앱 200에는 없음; Cloudflare 403 페이지에만 존재) → **클릭재킹** 가능.
- `Referrer-Policy` (앱 200에는 없음).
- `Permissions-Policy` (없음).

> 참고: 오래된 `P3P: CP="ALL CURa ADMa..."` 헤더 존재. 과거 IE 쿠키정책 우회에 쓰이던 무의미/구식 헤더로 제거 권장.

### 🟠 F-05 (Medium) 구버전 프론트엔드 라이브러리
- `jQuery 1.11.3` (2015년, EOL) — 알려진 이슈(예: 크로스도메인 `$.ajax` 관련 XSS, CVE-2015-9251 계열)에 노출. jQuery 3.5+ 권장.
- `jquery-migrate 1.2.1`, `jquery.cookie 1.4.1` 등 다수 노후 라이브러리.

### 🟠 F-06 (Medium) 외부 스크립트 SRI(무결성) 미적용 — 공급망 위험
`integrity=` 속성 **0개**. 외부 호스트에서 직접 로드:

```
https://cdnjs.cloudflare.com/.../moment.min.js
https://cdnjs.cloudflare.com/.../moment-timezone-with-data.min.js
https://cdnjs.cloudflare.com/.../jquery.cookie.min.js
https://player.vimeo.com/api/player.js
https://embed.tawk.to/636de426b0d6371309ce753d/...
```

- 외부 CDN이 변조/탈취되면 임의 스크립트가 사용자 브라우저(로그인 세션 컨텍스트)에서 실행. → `integrity`+`crossorigin` 또는 자가호스팅 권장.

### 🟠 F-07 (Medium, 확인필요) 로그인 CSRF/자동화 방어 부족
- 로그인 처리(`/post/login_ok.php`)는 **CSRF 토큰 없이** `login_id`/`login_pw`만으로 처리됨(단일 요청으로 확인). `SameSite`도 없어(F-01) **로그인 CSRF** 가능성.
- `/js/login.js`에 **보안코드(캡차) 검증이 주석 처리**되어 비활성:

```js
// check = $("#login-code"); ... // 보안코드 입력 검증 — 주석 처리됨
```

- 즉 캡차 없음 + (레이트리밋 여부 미확인) → **브루트포스/크리덴셜 스터핑** 노출 가능. (본 점검에서는 정책상 브루트포스 미수행)

**긍정적 관측:** 실패 응답이 일반 메시지(`"로그인 정보가 올바르지 않습니다."`)로, **사용자 열거(user enumeration) 미유발**. 양호.

### 🟡 F-08 (Low/확인필요) 세션 고정(Session Fixation) 가능성
- **실패한 로그인**에도 매번 **새 `PHPSESSID` 발급**이 관측됨. 로그인 성공 시 세션ID가 **재생성(regenerate)** 되는지 화이트박스로 확인 필요(안 되면 세션 고정).

### 🟡 F-09 (Low/Info) 오류 처리·정보 노출
- `GET /ajax/` → **HTTP 500**(디렉터리 직접 접근 시 내부 오류). 상세 오류/스택 노출 여부 화이트박스 확인.
- 다수 민감경로(`/.git/config`, `/.env`, `/phpinfo.php`, `/config.php`, `/.htaccess`, `/server-status`)는 `403`(Cloudflare 차단)로, **부재 단정 불가** → 오리진 직접 확인 필요.
- `expires: Thu, 19 Nov 1981`, `pragma: no-cache` 등 레거시 PHP 기본 헤더 잔존(무해하나 정리 권장).

### 🟡 F-10 (Info/Privacy) 장기 추적 쿠키
- `UUID` 쿠키가 **Max-Age 1년**, 플래그 없이 설정. 개인정보/추적 관점 검토 및 플래그 부여 권장.

---

## 3. 공격 표면 인벤토리 (화이트박스 대상 엔드포인트)

HTML/JS에서 식별된 서버 엔드포인트 — 화이트박스에서 입력검증/권한/쿼리를 집중 리뷰:

| 엔드포인트 | 성격 | 우선 점검 항목 |
|---|---|---|
| `/post/login_ok.php` | 로그인 처리(POST) | SQLi, 레이트리밋, 세션재생성, CSRF, 계정잠금 |
| `/post/community_binding.php` | 커뮤니티/바인딩(POST) | 인증확인, IDOR, 입력검증 |
| `/ajax/money_rank.php` | 금액 랭킹(AJAX) | 정보노출, 권한, SQLi |
| `/index.php` | 메인 | 파라미터 반영/XSS |
| `/casino-ab.php` `/casino-ag.php` `/casino-eg.php` `/casino-mg.php` `/casino-pr.php` | 카지노 게임 연동 | 프로바이더 콜백 검증, SSRF, 서명검증 |
| `/sports-bti.php` `/sports-pinnacle.php` `/sports-sbo.php` | 스포츠북 연동 | 콜백/토큰 검증, 금액 변조 |
| `/casino/slot/mg_demo.php?game=SMG_...` | 슬롯 데모(GET, `game` 파라미터) | **경로순회/LFI/인젝션**(파라미터가 파일/쿼리에 쓰이는지) |
| `/casino/slot/mg_demo_free.php?game=...` | 슬롯 데모 무료 | 동일 |

> 카지노/스포츠 도메인 특성상 **금전 로직**(입출금, 포인트/롤링, 쿠폰, 베팅 정산)이 최우선 리뷰 대상입니다: 금액/수량 **서버측 재검증**, **원자적 트랜잭션**, **IDOR**(타인 계정 자금 접근), **경쟁조건(race condition)**(중복 출금/베팅), **음수/오버플로우**.

---

## 4. 화이트박스 단계 점검 계획 (소스 확보 후)

1. **인젝션:** `login_ok.php` 등에서 PDO/prepared statement 사용 여부, `mg_demo.php`의 `game` 처리(파일 include 여부).
2. **XSS 싱크:** 서버 응답 생성 시 사용자 입력 escape 여부(F-02의 `eval`/`$(s).html(d)` 대응). 저장형/반사형 모두.
3. **인증/세션:** 로그인 성공 시 `session_regenerate_id(true)` 호출 여부, 쿠키 플래그 설정부(`session.cookie_httponly/secure/samesite`), 로그아웃 무효화.
4. **CSRF:** 상태변경 POST(입출금/포인트/설정)에 토큰 검증 존재 여부.
5. **인가/IDOR:** 사용자 식별을 세션에서 가져오는가, 아니면 클라이언트 파라미터(`user_id` 등)를 신뢰하는가.
6. **금전 로직:** 입출금/베팅/롤링 계산의 서버측 검증·트랜잭션·경쟁조건.
7. **오픈 리다이렉트:** `r.move`/`r.replace`에 들어가는 URL의 출처(사용자 입력 → 검증 없이 반영 여부).
8. **에러/로그:** `display_errors` off 여부, 예외/스택 미노출, 민감정보 로깅 여부.
9. **업로드/파일:** 아바타/증빙 업로드가 있으면 확장자/콘텐츠타입/경로 처리.

---

## 5. 즉시 적용 가능한 완화책 (코드 없이 인프라/설정 레벨)

화이트박스 이전에도 **Cloudflare/서버 설정**만으로 리스크를 낮출 수 있는 항목:

- **응답 보안 헤더 추가**(Cloudflare Transform Rules 또는 웹서버):
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN` (또는 CSP `frame-ancestors 'self'`)
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Security-Policy`(우선 Report-Only로 시작 → 인라인 스크립트/eval 정리 후 강화)
  - `Permissions-Policy`(불필요 기능 차단)
- **쿠키 플래그**: PHP `session.cookie_httponly=1`, `cookie_secure=1`, `cookie_samesite=Lax|Strict`; `UUID`에도 동일 적용. 쿠키 `domain`을 필요한 최소 범위로.
- **로그인 캡차 재활성화**(주석 해제) + **레이트리밋/계정 잠금**(Cloudflare Rate Limiting Rules).
- **P3P 헤더 제거**, 레거시 캐시 헤더 정리.
- **외부 스크립트 SRI 적용** 또는 자가호스팅, **jQuery 등 라이브러리 최신화**.
- 민감경로가 오리진에 실제 존재하는지 확인 후 접근차단(오리진은 Cloudflare 우회 접근도 대비).

---

## 6. 부록 — 재현용 관측 명령(비파괴)

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/126 Safari/537.36"
# 앱 실제 응답 헤더/쿠키
curl -sS -D - -o /dev/null -A "$UA" https://www.dw-04.com/
# HTTP→HTTPS 리다이렉트(HSTS 부재 확인)
curl -sS -D - -o /dev/null -A "$UA" http://www.dw-04.com/
# 로그인 오류 응답(사용자 열거 미유발 확인)
curl -sS -A "$UA" --data "login_id=INVALID&login_pw=INVALID" \
  https://www.dw-04.com/post/login_ok.php
```

---

*본 리포트는 소유자 승인 하에 수행된 블랙박스 점검 결과입니다. 실제 익스플로잇 여부·상세 수정안은 화이트박스(소스코드) 단계에서 확정합니다.*
