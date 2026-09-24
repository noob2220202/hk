# dwdw-00.com 인증 보안 테스트 리포트

- **대상(Target):** `https://www.dwdw-00.com/` (대왕 카지노)
- **점검 유형:** 인증(Authenticated) 블랙박스 — 로그인 후 공격적 테스트
- **테스트 계정:** `rnalswo` / `[REDACTED]`
- **권한(Authorization):** 사이트 소유자/운영자 본인이 점검을 요청·승인 (self-owned)
- **원칙:** 비파괴(non-destructive) — 실제 자금 변조/이체 미수행, 데이터 삭제 없음
- **작성일:** 2026-09-24
- **이전 리포트:** `dw-04.com` 블랙박스 보안 점검 리포트 (2026-08-05)
- **환경:** Cloudflare WAF 뒤에 위치, Apache/2.4.52 (Ubuntu), PHP 백엔드

---

## 0. 요약 (Executive Summary)

dwdw-00.com은 dw-04.com과 **동일한 코드베이스**를 사용하며, 이전 리포트에서 발견된 취약점이 **모두 그대로 존재**합니다. 추가로 **인증 후 테스트에서 최고 위험도의 신규 취약점**이 발견되었습니다:

| 심각도 | 발견 수 | 핵심 |
|--------|---------|------|
| 🟥 Critical | 2 | 자격증명 평문 노출, 반사형 XSS |
| 🔴 High | 3 | 세션 고정, 쿠키 플래그 누락, eval 기반 코드실행 |
| 🟠 Medium | 5 | HSTS 미설정, 보안헤더 부재, CSRF 토큰 없음, 미인증 정보노출, 구버전 라이브러리 |
| 🟡 Low/Info | 4 | 캡차 비활성, 디버그 코드, Apache 버전 노출, 장기 추적 쿠키 |

**최우선 대응 필요:** F-NEW-01(자격증명 노출)은 즉시 수정이 필요합니다.

---

## 1. 기술 스택 (동일 확인)

| 항목 | 관측값 |
|---|---|
| CDN/WAF | Cloudflare (cf-ray, nel, report-to) |
| 웹서버 | Apache/2.4.52 (Ubuntu) — **404 오류 페이지에서 버전 노출** |
| 백엔드 | PHP (PHPSESSID) |
| 프론트 | jQuery 1.11.3, jquery-migrate 1.2.1, jquery.tmpl, sweetalert2, bxSlider, waterwheelCarousel |
| 서드파티 | Tawk.to (636de426...), Vimeo, cdnjs.cloudflare.com, Cloudflare Web Analytics |
| 시간대 | Asia/Tokyo (moment-timezone) |
| 도메인 | dwdw-00.com (이전: dw-04.com — 동일 코드베이스) |

---

## 2. 발견 사항 (Findings)

### 🟥 F-NEW-01 (Critical, 확정) 자격증명 평문 노출 — `community_binding.php`

**가장 심각한 신규 발견.** `/post/community_binding.php`는 로그인한 사용자의 **외부 커뮤니티 사이트 자격증명(uid, pwd)을 평문 JSON으로 반환**합니다.

```
POST /post/community_binding.php
(인증된 세션, 별도 파라미터 불필요)

응답:
{"url" : "http://www.flower-01.com/bbs/login.php?uid=rnalswo&pwd=[REDACTED]&ch=23", "pwd" : "[REDACTED]"}
```

**위험 분석:**
- **자격증명 URL 포함:** 사용자 ID와 비밀번호가 **GET 파라미터에 평문**으로 포함. URL은 브라우저 히스토리, 서버 액세스 로그, Referer 헤더, 프록시 로그 등에 기록됨.
- **HTTP(비암호화) 전송:** 대상 URL이 `http://` (HTTPS 아님) — 네트워크 도청으로 자격증명 탈취 가능.
- **CSRF 토큰 없음:** POST 요청이지만 토큰 검증 없이 세션 쿠키만으로 동작 → XSS(F-00)와 결합하면 공격자가 피해자의 커뮤니티 자격증명을 원격 탈취 가능.
- **GET 요청으로도 동작:** `GET /post/community_binding.php`로도 동일 응답 반환 → CSRF 공격 시 더 쉬움.
- **파라미터 불필요:** `type` 파라미터 유무와 관계없이 동일 응답.
- **호출 코드:** `function.js`의 `goToCommunity()` 함수가 이 엔드포인트를 호출하여 `confirm()` 다이얼로그로 비밀번호 표시 후 `window.open()`으로 자동 로그인.

**공격 체인:**
1. F-00(반사형 XSS) + F-NEW-01 → 조작된 링크로 피해자의 커뮤니티 계정 자격증명 원격 탈취
2. F-01(HttpOnly 없는 세션쿠키) + F-NEW-01 → 세션 하이재킹 후 모든 사용자의 커뮤니티 자격증명 수집

**즉시 조치:**
- 비밀번호를 URL GET 파라미터로 전달하지 말 것
- 서버간 토큰 기반 SSO 구현 (OAuth/SAML)
- 최소한 POST 전용 + CSRF 토큰 적용
- 커뮤니티 비밀번호를 클라이언트에 노출하지 않는 구조로 변경

---

### 🟥 F-00 (Critical, 확정) 반사형 XSS — 슬롯 데모 `game` 파라미터

dw-04.com과 **동일한 취약점이 dwdw-00.com에도 존재** 확인:

```
GET /casino/slot/mg_demo_free.php?game=MARKER'BREAK
응답(인라인 JS): gameid: 'MARKER'BREAK'}
```

| 페이로드(`game=`) | 반영 결과 |
|---|---|
| `abc'def` | `gameid: 'abc'def'` — **단일따옴표 탈출** |
| `a'};//X` | `gameid: 'a'};//X'` — **JS 문자열 탈출+코드주입** |
| `abc"def` | `gameid: 'abc"def'` — 이중따옴표 원본 반영 |
| `abc<def` | `gameid: 'abc<def'` — 꺾쇠 원본 반영 |
| `abc`def` | ``gameid: 'abc`def'`` — 백틱 원본 반영 |

- **WAF(Cloudflare)는 `<script>`, `alert(` 같은 시그니처만 차단** — 문자열 탈출 프리미티브(`'};`)는 통과.
- **F-01(HttpOnly 없음) + F-00 → 세션 하이재킹/계정 탈취 가능.**
- **F-NEW-01 + F-00 → 피해자의 커뮤니티 자격증명까지 원격 탈취.**

디버그 코드 잔존 확인: `console.log("Fuck");` 포함.

---

### 🔴 F-01 (High, 확정) 세션 쿠키 보안 플래그 전면 누락

```
PHPSESSID: httpOnly=false  secure=false  sameSite=Lax  domain=.dwdw-00.com
UUID:      httpOnly=false  secure=false  sameSite=Lax  domain=.dwdw-00.com  expires=2027-09-24
```

- **`HttpOnly` 없음** → XSS에서 `document.cookie`로 세션 탈취 가능
- **`Secure` 없음** → HTTPS 전용 강제 안 됨
- `domain=.dwdw-00.com` → 모든 서브도메인으로 쿠키 공유

> 참고: `SameSite=Lax`가 관측됨 (dw-04.com에서는 없었음). 브라우저 기본값일 수 있으나, 명시적 설정인지 화이트박스 확인 필요.

---

### 🔴 F-NEW-02 (High, 확정) 세션 고정(Session Fixation)

**로그인 전후 세션ID 변경 확인 결과:**

```
Pre-login  PHPSESSID: n8od69h21snf8rh0nsor7nm6vn
Post-login PHPSESSID: n8od69h21snf8rh0nsor7nm6vn  ← 동일!
Session regenerated on login: FALSE
```

```
Pre re-login  PHPSESSID: 5ks1vtdieu9vlkgc00515klubj
Post re-login PHPSESSID: 5ks1vtdieu9vlkgc00515klubj  ← 동일!
Session regenerated on login: FALSE
```

- **로그인 성공 시 `session_regenerate_id()` 호출 안 됨** → **세션 고정 공격 가능**
- 공격자가 피해자에게 알려진 세션ID를 주입(Set-Cookie via XSS 또는 HTTP) → 피해자 로그인 시 공격자가 동일 세션으로 접근
- **로그아웃 시에는 세션이 변경됨** (양호): `uslraft...` → `096tolo...` (새 세션 발급)

**수정:** `login_ok.php`에서 인증 성공 후 `session_regenerate_id(true)` 호출 추가.

---

### 🔴 F-02 (High, 확정) 클라이언트가 서버 응답을 `eval()` — 광범위한 코드실행

`/js/ajax_call.js` (6,237 bytes) 분석 — **6개의 eval() 사용 확인:**

```js
eval("(function( event ){" + p + "}).apply( n, [ k ] )")  // ajax-precall 속성값 실행
eval("o=" + this.getAttribute("ajax"))                     // ajax 속성값을 코드로 평가 (2회)
eval("r=" + d)                                              // 서버 응답 본문을 코드로 평가
eval("s=" + (a ? a : null))                                 // 응답 필드를 코드로 평가
eval(r.callback)                                            // 서버 응답의 callback 필드를 실행
```

- `$(s).html(d)` — 서버 응답을 인코딩 없이 DOM에 삽입 (1개 HTML 싱크)
- `location` 관련 조작 4건 — 서버 응답의 `r.move`/`r.replace`로 리다이렉트

**영향:** 서버 응답이 변조되거나 사용자 입력이 반영되면 임의 스크립트 실행. `function.js`에서도 `eval("popup_options=" + popup_str)` 사용 확인.

---

### 🟠 F-03 (Medium, 확정) HSTS 미설정 + 모든 보안 헤더 부재

응답 헤더 분석 (200 OK 응답 기준):

| 보안 헤더 | 상태 |
|---|---|
| `Strict-Transport-Security` | **MISSING** |
| `Content-Security-Policy` | **MISSING** |
| `X-Content-Type-Options` | **MISSING** |
| `X-Frame-Options` | **MISSING** |
| `Referrer-Policy` | **MISSING** |
| `Permissions-Policy` | **MISSING** |
| `X-XSS-Protection` | **MISSING** |

- 구식 `P3P` 헤더 존재 (무의미, 제거 권장)
- `expires: Thu, 19 Nov 1981` — PHP 기본 레거시 헤더 잔존

---

### 🟠 F-NEW-03 (Medium, 확정) CSRF 토큰 부재 — 모든 상태변경 요청

**인증 후 페이지 분석 결과:**
- CSRF 메타 태그: **없음**
- 토큰 hidden input: **없음**
- 발견된 hidden input: `success` 필드만 존재 (CSRF 토큰 아님)

**상태변경 POST 엔드포인트에 CSRF 보호 없음:**
- `/post/login_ok.php` — 로그인 (로그인 CSRF)
- `/post/community_binding.php` — 커뮤니티 바인딩 (자격증명 노출)
- `/post/exchange_ok.php` — **카지노 머니 이체** (TransferMoney 함수)
- `/post/checkCasinoStat.php` — 카지노 상태 확인
- `/ajax/callapi.php` — 게임 API (checkUser, 잔액 조회)

**`SameSite=Lax`가 일부 방어하나**, GET 요청으로도 작동하는 엔드포인트(F-NEW-01)에는 무효.

---

### 🟠 F-11 (Medium, 확정) 미인증 정보 노출 — 랭킹/API 오류

1. **`/ajax/money_rank.php`** — **비로그인으로 접근 가능**, 사용자 활동 노출:
   - 마스킹 아이디: `mo***4`, `ce***6`, `th***282` 등
   - 금액: `570,000 원` ~ `30,000,000 원`
   - 시각: `09/24 18:28` 등 정확한 거래 시각

2. **`/ajax/callapi_free.php`** — **미인증 API 디스패처**, 상위 게임 API 오류 프록시:
   ```xml
   <returndata>400{"error":{"code":"GameDoesNotExist",
     "message":"Game does not exist for Agent",
     "message-zh-CHS":"游戏对代理人不存在"}}</returndata>
   ```
   → 에이전트 구조, 상위 API 엔드포인트 정보 노출

---

### 🟠 F-05 (Medium) 구버전 프론트엔드 라이브러리

| 라이브러리 | 버전 | 위험 |
|---|---|---|
| jQuery | 1.11.3 (2015, EOL) | CVE-2015-9251 계열 XSS |
| jquery-migrate | 1.2.1 | 구버전 |
| jquery.cookie | 1.4.1 | 구버전, CDN 로드 |
| moment.js | 2.17.1 (cdnjs) | 구버전 |
| moment-timezone | 0.5.10 (cdnjs) | 구버전 |

**SRI(Subresource Integrity) 미적용:** 모든 외부 스크립트에 `integrity` 없음.

---

### 🟡 F-07 (Low, 확정) 로그인 보안코드(캡차) 비활성

`/js/login.js` 확인 — 보안코드 검증 **주석 처리**:

```js
// check = $("#login-code");
// if (!check.val()) {
//     alert("보안코드를 입력해 주세요.");
//     check.focus();
//     return false;
// }
```

- 캡차 없음 → 브루트포스/크리덴셜 스터핑 노출
- **긍정적:** 로그인 실패 시 일반 메시지("로그인 정보가 올바르지 않습니다.") → 사용자 열거 미유발
- **긍정적:** SQLi 페이로드에 대해 모두 동일한 오류 메시지 반환 → 준비된 쿼리(prepared statement) 사용 추정

---

### 🟡 F-NEW-04 (Info, 확정) Apache 버전 노출

404 오류 페이지에서 서버 정보 노출:
```
Apache/2.4.52 (Ubuntu) Server at www.dwdw-00.com Port 80
```

- 내부적으로 **HTTP(Port 80)**로 서비스 → Cloudflare가 HTTPS 종단
- 서버 버전 정보는 공격자의 취약점 매칭에 활용 가능

---

### 🟡 F-NEW-05 (Info, 확정) 프로덕션 디버그 코드

슬롯 데모 페이지의 인라인 스크립트:
```js
console.log("Fuck");
console.log(xml);
console.log(returndata);
console.log("done");
```

- 비속어 포함 디버그 코드 잔존
- `xml`, `returndata` 콘솔 출력 → 정보 유출

---

### 🟡 F-10 (Info) 장기 추적 쿠키

```
UUID: expires=2027-09-24 (1년), httpOnly=false, secure=false
```

---

## 3. 금전 로직 공격 표면 (인증 후 발견)

JS 분석으로 식별된 **금전 관련 기능:**

| 함수/엔드포인트 | 기능 | 위험 |
|---|---|---|
| `TransferMoney()` → `/post/exchange_ok.php` | 카지노 머니 이체 | **CSRF 토큰 없음**, 금액 클라이언트 입력(`$(elm).val()`), `eval` 기반 콜백 |
| `refresh_casino()` → `/ajax/callapi.php` `checkUser` | 카지노 잔액 조회 | 미인증 가능성 |
| `getCasinoMoney()` → `/ajax/callapi.php` `checkUser` | 카지노 머니 표시 | 동일 |
| `popup_deposit()` → `/ajax/popup_deposit.php` | 입금 요청 | HTML 응답을 `swal` 팝업에 삽입 |
| `popup_coin_deposit()` → `/ajax/popup_coin_deposit.php` | 코인 입금 | 동일 |
| `goToCommunity()` → `/post/community_binding.php` | 커뮤니티 자동로그인 | **F-NEW-01: 자격증명 평문 노출** |

**화이트박스 최우선 점검 대상:**
1. `exchange_ok.php` — 금액 서버측 검증, 트랜잭션 원자성, 경쟁조건
2. `callapi.php` — 인증 확인, IDOR, 금액 변조
3. `popup_deposit.php` / 입출금 처리 — 인증, 금액 검증

---

## 4. 인증/세션 관리 종합 평가

| 항목 | 상태 | 평가 |
|---|---|---|
| 로그인 성공 시 세션 재생성 | **안 됨** | 🔴 취약 (세션 고정) |
| 로그아웃 시 세션 무효화 | **새 세션 발급** | 🟢 양호 |
| 쿠키 HttpOnly | **미설정** | 🔴 취약 |
| 쿠키 Secure | **미설정** | 🔴 취약 |
| 쿠키 SameSite | `Lax` (관측) | 🟡 부분 양호 |
| CSRF 토큰 | **없음** | 🔴 취약 |
| 캡차/레이트리밋 | **캡차 주석처리** | 🟠 취약 |
| 사용자 열거 | **미유발** | 🟢 양호 |
| SQLi 방어 | **작동 추정** | 🟢 양호 (화이트박스 확인 필요) |
| 비밀번호 평문 전송 | **커뮤니티: 평문** | 🔴 치명적 |

---

## 5. 민감 경로 스캔 결과

| 경로 | 상태 | 비고 |
|---|---|---|
| `/.env` | 403 (WAF) | 부재 단정 불가 |
| `/.git/config` | 403 (WAF) | 부재 단정 불가 |
| `/.git/HEAD` | 403 (WAF) | 부재 단정 불가 |
| `/config.php` | 403 (WAF) | 부재 단정 불가 |
| `/.htaccess` | 403 (Apache) | 접근 차단 확인 |
| `/server-status` | 403 (Apache) | 접근 차단 확인 |
| `/robots.txt` | 200 | Cloudflare 기본 robots.txt (콘텐츠 신호) |
| `/admin/` | 연결 실패 | WAF 완전 차단 |
| `/adm/`, `/manage/`, `/phpinfo.php` 등 | 404 | 미존재 |

---

## 6. dw-04.com과의 비교 (동일 코드베이스 확인)

| 항목 | dw-04.com | dwdw-00.com | 동일여부 |
|---|---|---|---|
| 반사형 XSS (F-00) | ✅ 확정 | ✅ 확정 | 동일 |
| 쿠키 플래그 (F-01) | HttpOnly/Secure 없음 | HttpOnly/Secure 없음 | 동일 |
| eval 기반 (F-02) | 6개 eval | 6개 eval | 동일 |
| HSTS (F-03) | 없음 | 없음 | 동일 |
| 보안헤더 (F-04) | 전부 없음 | 전부 없음 | 동일 |
| jQuery (F-05) | 1.11.3 | 1.11.3 | 동일 |
| SRI (F-06) | 없음 | 없음 | 동일 |
| 캡차 (F-07) | 주석처리 | 주석처리 | 동일 |
| 랭킹 노출 (F-11) | 확정 | 확정 | 동일 |
| callapi_free (F-12) | 확정 | 확정 | 동일 |
| 디버그 코드 (F-13) | console.log("Fuck") | console.log("Fuck") | 동일 |
| **커뮤니티 자격증명 (F-NEW-01)** | 미테스트 | ✅ **Critical 확정** | 신규 |
| **세션 고정 (F-NEW-02)** | 잠재 | ✅ **확정** | 신규 확정 |

---

## 7. 즉시 대응 우선순위

### 최우선 (즉시)
1. **F-NEW-01:** `community_binding.php` — 비밀번호를 클라이언트에 반환하지 않도록 변경. 서버간 토큰 기반 SSO로 교체. 최소한 HTTPS + POST 전용 + CSRF 토큰.
2. **F-00:** `mg_demo_free.php` / `mg_demo.php` — `game` 파라미터를 `^[A-Za-z0-9_]+$` 허용목록 검증 + `json_encode()`로 JS 컨텍스트 인코딩.
3. **F-01:** PHP 설정에 `session.cookie_httponly=1`, `session.cookie_secure=1`, `session.cookie_samesite=Strict` 적용.

### 긴급 (1주 내)
4. **F-NEW-02:** `login_ok.php`에서 `session_regenerate_id(true)` 호출 추가.
5. **F-03/F-04:** Cloudflare Transform Rules로 보안 헤더 일괄 추가.
6. **CSRF 토큰:** 모든 상태변경 POST에 토큰 검증 추가 (특히 `exchange_ok.php` 금전 이체).

### 중기 (1개월)
7. **F-02:** `eval()` 제거 → `JSON.parse()` 전환, `$(s).html(d)` 대신 안전한 DOM 조작.
8. **F-05:** jQuery 3.5+ 업그레이드, 외부 스크립트 SRI 적용.
9. **F-07:** 캡차 재활성화 + 레이트리밋.
10. **Apache `ServerTokens Prod`** 설정으로 버전 노출 차단.

---

## 8. 부록 — 재현 명령 (비파괴)

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126 Safari/537.36"

# F-NEW-01: 커뮤니티 자격증명 노출 (인증 필요)
# 먼저 로그인 후 PHPSESSID 쿠키 획득
curl -sS -c cookies.txt -A "$UA" \
  --data "login_id=<USER>&login_pw=<PASS>" \
  https://www.dwdw-00.com/post/login_ok.php

# 자격증명 평문 반환 확인
curl -sS -b cookies.txt -A "$UA" \
  https://www.dwdw-00.com/post/community_binding.php

# F-00: XSS 반영 확인
curl -sS -b cookies.txt -A "$UA" \
  "https://www.dwdw-00.com/casino/slot/mg_demo_free.php?game=abc%27def" | grep gameid

# F-NEW-02: 세션 고정 확인 (로그인 전후 PHPSESSID 비교)
curl -sS -D - -o /dev/null -c cookies2.txt -A "$UA" https://www.dwdw-00.com/
grep PHPSESSID cookies2.txt
curl -sS -b cookies2.txt -A "$UA" \
  --data "login_id=<USER>&login_pw=<PASS>" \
  https://www.dwdw-00.com/post/login_ok.php
# PHPSESSID가 변경되지 않으면 세션 고정 취약

# F-11: 미인증 랭킹 노출
curl -sS -A "$UA" https://www.dwdw-00.com/ajax/money_rank.php | head -20

# 쿠키 플래그 확인
curl -sS -D - -o /dev/null -A "$UA" https://www.dwdw-00.com/ 2>&1 | grep -i set-cookie

# 보안 헤더 확인
curl -sS -D - -o /dev/null -A "$UA" https://www.dwdw-00.com/ 2>&1 | \
  grep -iE "strict-transport|content-security|x-content-type|x-frame|referrer-policy"
```

---

*본 리포트는 소유자 승인 하에 수행된 인증(authenticated) 보안 테스트 결과입니다. 비파괴 원칙을 준수했으며, 실제 금전 변조·이체·데이터 삭제는 수행하지 않았습니다.*
