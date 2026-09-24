# 블랙박스 보안 테스트 보고서

**대상**: https://www.dwdw-00.com (대왕 카지노)  
**테스트 일자**: 2026-09-24  
**테스트 유형**: 블랙박스 (외부 관점, 비인증)

---

## 1. 기술 스택 식별

| 구분 | 기술 | 버전/비고 |
|------|------|-----------|
| **백엔드** | PHP | PHPSESSID 쿠키로 확인 |
| **CDN/WAF** | Cloudflare | HTTP/2, cf-ray 헤더 |
| **프론트엔드** | jQuery | **1.11.3** (데스크탑) / **1.12.0** (모바일) |
| **라이브러리** | jQuery Migrate | 1.2.1 |
| **라이브러리** | jQuery Template | jquery.tmpl.js |
| **라이브러리** | moment.js | **2.17.1** |
| **라이브러리** | moment-timezone | **0.5.10** |
| **UI** | SweetAlert2 | 커스텀 빌드 |
| **UI** | Font Awesome | (버전 미상) |
| **UI** | Bootstrap | (모바일만, 버전 미상) |
| **슬라이더** | bxSlider, multislider, waterwheel carousel | |
| **채팅** | Tawk.to | 위젯 ID: `636de426b0d6371309ce753d` |
| **비디오** | Vimeo Player API | |
| **레거시** | Flash (Shockwave) | 코드에 Flash 함수 잔존 |

---

## 2. 심각도별 취약점 분류

### CRITICAL (즉시 조치 필요)

#### C-01: 다수의 `eval()` 사용으로 인한 코드 인젝션 위험
- **위치**: `/js/ajax_call.js` (라인 17, 28, 88, 138, 150, 194)
- **설명**: `ajax_call()`, `ajax_call_force()`, `callback_default()`, `callback_html()`, `post_result_default()` 함수에서 서버 응답 및 HTML 속성 값을 `eval()`로 실행
- **영향**: 서버 응답이 변조되거나 HTML 속성이 조작되면 임의 JavaScript 실행 가능
- **코드 예시**:
```javascript
// ajax_call.js:28 - HTML 속성을 eval로 실행
eval("o=" + this.getAttribute("ajax"))

// ajax_call.js:138 - 서버 응답을 eval로 파싱
eval("r=" + d)

// ajax_call.js:194 - 서버의 callback 문자열을 eval로 실행
eval(r.callback)
```

#### C-02: CSRF 토큰 부재
- **위치**: 로그인 폼 및 모든 AJAX POST 요청
- **설명**: 어떤 form이나 AJAX 호출에도 CSRF 토큰이 없음
- **영향**: 공격자가 사용자의 세션을 이용해 충전/환전/비밀번호 변경 등 모든 작업을 대리 수행 가능
- **증거**: 로그인 폼에 `<input type="hidden">` 이 `success` redirect 값만 있음, CSRF 토큰 없음

#### C-03: 커뮤니티 바인딩 API가 비밀번호를 평문 노출
- **위치**: `/post/community_binding.php`
- **설명**: `goToCommunity()` 함수가 호출되면 JSON으로 `pwd` 값이 평문으로 반환됨
- **코드 증거**:
```javascript
// function.js:271-283
$.ajax({
    url: '../post/community_binding.php',
    success: function(data) {
        data = JSON.parse(data);
        msg = "커뮤니티 접속 비밀번호는 " + data['pwd'] + "입니다.";
    }
});
```

#### C-04: `.git` 디렉터리 접근 가능 (Cloudflare에 의해 차단 중)
- **위치**: `/.git/config`
- **상태**: HTTP 403 (Cloudflare WAF가 차단 중)
- **위험**: Cloudflare 우회 시 전체 소스코드, 커밋 히스토리, 크레덴셜 노출 가능
- **비고**: 403 응답은 파일이 서버에 존재함을 의미. origin 서버 IP 노출 시 직접 접근 가능

#### C-05: `.env` 파일 존재
- **위치**: `/.env`
- **상태**: HTTP 403 (Cloudflare WAF가 차단 중)
- **위험**: 환경변수 파일에 DB 크레덴셜, API 키 등 민감정보 포함 가능

---

### HIGH (높은 위험)

#### H-01: 구식 jQuery (1.11.3/1.12.0) - 알려진 XSS 취약점 다수
- **CVE 목록**:
  - CVE-2015-9251: jQuery 3.0.0 미만 크로스 사이트 스크립팅
  - CVE-2019-11358: jQuery `extend()` 프로토타입 오염
  - CVE-2020-11022: jQuery `.html()` XSS
  - CVE-2020-11023: jQuery `.html()` XSS (추가 벡터)
- **영향**: `.html()` 호출이 코드 전반에 걸쳐 사용되며, 서버 응답을 직접 삽입

#### H-02: XSS 취약점 - 서버 응답의 비가공 DOM 삽입
- **위치**: 다수의 popup 함수 (`popup_event.js`)
- **예시 코드**:
```javascript
// popup_event.js - 서버 응답을 직접 HTML로 삽입
buf.push('<td class="msg" id="ic">' + data + '</td>');
swal({ html: buf.join('') });
```
- **영향**: 서버 응답에 `<script>` 태그가 포함되면 실행됨

#### H-03: 쿠키 보안 미흡
- **PHPSESSID**: `HttpOnly`, `Secure`, `SameSite` 플래그 모두 없음
- **UUID**: `HttpOnly` 없음, 도메인 범위가 `.dwdw-00.com`으로 서브도메인 전체에 공유
- **증거**:
```
Set-Cookie: PHPSESSID=ad6ebd5vee4t3teglg658lhfjv; path=/; domain=.dwdw-00.com
Set-Cookie: UUID=abb47643c35d8918cc220b98649dd270260924124409; expires=...; path=/; domain=.dwdw-00.com
```

#### H-04: URL 파라미터 인젝션 (XSS/인젝션)
- **위치**: 다수의 PHP 파일에 GET 파라미터를 iframe으로 삽입
- **취약 URL 패턴**:
  - `/board-read.php?no=` + 사용자 입력
  - `/notice-read.php?no=` + 사용자 입력
  - `/event-read.php?no=` + 사용자 입력
  - `/helpdesk-read.php?MsgNo=` + 사용자 입력
  - `/casino/slot/mg_demo.php?game=` + 사용자 입력
- **코드 증거**:
```javascript
buf.push('<iframe src="/board-read.php?no=' + bno + '"...');
buf.push('<iframe src="/helpdesk-read.php?MsgNo=' + param + '"...');
```
- **파라미터 값이 정수 검증 없이 직접 URL에 삽입됨**

#### H-05: 문자열 연결 기반 AJAX 속성 구성 (인젝션)
- **위치**: `/js/function.js:270-276` `TransferMoney()` 함수
- **설명**: 사용자 입력값이 문자열 연결로 `ajax` 속성에 삽입
```javascript
$(n).attr("ajax",
    "{url: '/post/exchange_ok.php',type:'post',data:{ site:'" + site + 
    "', ic_amount:'" + $(elm).val() + "', Category:'" + tp + "'}, success: TransferCallback}"
);
```
- **영향**: `site`, `ic_amount`, `tp` 값에 `'` 문자 삽입 시 JavaScript 인젝션

#### H-06: 보안 코드(캡차) 검증 비활성화
- **위치**: `/js/login.js:29-34`
- **설명**: 보안코드 검증 로직이 주석 처리되어 비활성화됨
```javascript
// check = $("#login-code");
// if (!check.val()) {
//     alert("보안코드를 입력해 주세요.");
//     check.focus();
//     return false;
// }
```

---

### MEDIUM (중간 위험)

#### M-01: 비인증 정보 노출 - 사용자 ID 및 거래 내역
- **위치**: `/ajax/money_rank.php`
- **설명**: 인증 없이 POST 요청만으로 접근 가능
- **노출 정보**:
  - 부분 마스킹된 사용자 ID (예: `rl***3`, `ca***n061`)
  - 충전/환전 금액 (예: `900,000 원`, `1,000,000 원`)
  - 거래 일시

#### M-02: Content-Security-Policy (CSP) 부재
- **설명**: 서버 응답에 CSP 헤더 없음
- **영향**: XSS 취약점 존재 시 외부 스크립트 로드 제한 없음

#### M-03: X-Content-Type-Options 헤더 부재
- **영향**: MIME 타입 스니핑을 통한 공격 가능

#### M-04: 과도하게 허용적인 P3P 정책
```
P3P: CP="ALL CURa ADMa DEVa TAIa OUR BUS IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC OTC"
```
- 거의 모든 데이터 수집을 허용하는 정책

#### M-05: moment.js 구버전 취약점
- **CVE-2022-24785**: 경로 순회 취약점
- **CVE-2022-31129**: ReDoS 취약점

#### M-06: 서버 오류 응답 노출
- **위치**: `/ajax/` 경로 직접 접근 시 HTTP 500 반환
- **위험**: 서버 오류 메시지가 디버그 정보 노출 가능

#### M-07: 민감 경로 존재 확인
| 경로 | 상태 | 의미 |
|------|------|------|
| `/.env` | 403 | 환경변수 파일 존재 |
| `/.git/config` | 403 | Git 저장소 노출 |
| `/.htaccess` | 403 | Apache 설정 파일 존재 |
| `/config.php` | 403 | 설정 파일 존재 |
| `/inc/` | 403 | 인클루드 디렉터리 존재 |
| `/phpmyadmin/` | 403 | phpMyAdmin 설치됨 |
| `/post/` | 403 | POST 핸들러 디렉터리 |
| `/casino/` | 403 | 카지노 디렉터리 |

---

### LOW (낮은 위험)

#### L-01: Flash (Shockwave) 레거시 코드 잔존
- **위치**: `/js/function.js:186-199`
- **설명**: `flash()` 함수가 Flash Object/Embed 태그를 생성하는 코드가 여전히 존재
- **HTTP 프로토콜 사용**: `http://download.macromedia.com/...`

#### L-02: document.write 사용
- **위치**: `/js/function.js:211` `print_server_time()` 함수
- **영향**: DOM 조작 시점에 따라 페이지 전체 덮어쓰기 가능

#### L-03: Tawk.to 위젯 ID 노출
- **ID**: `636de426b0d6371309ce753d/1ghik6dtq`
- **영향**: 위젯 설정 정보 유추 가능

#### L-04: 텔레그램 고객센터 ID 노출
- **ID**: `dcenter3`
- **위치**: HTML 인라인 (`telegram.me/dcenter3`)

#### L-05: 도메인 정보 JavaScript 변수로 노출
```javascript
var VARS = {
    pageToken: "index",
    domain: "dwdw-00.com",
    ...
}
```

---

## 3. 발견된 엔드포인트 매핑

### POST 핸들러 (`/post/`)
| 엔드포인트 | 기능 | 인증 필요 |
|-----------|------|----------|
| `/post/login_ok.php` | 로그인 처리 | N/A |
| `/post/exchange_ok.php` | 머니 이체 | Yes |
| `/post/checkCasinoStat.php` | 카지노 상태 확인 | Unknown |
| `/post/community_binding.php` | 커뮤니티 연동 (비밀번호 노출) | Yes |
| `/post/ask_get_mileage.php` | 콤프/마일리지 수령 | Yes |
| `/post/get_roll_point.php` | 롤링 포인트 지급 | Yes |
| `/post/get_roll_point_v2.php` | 롤링 포인트 v2 | Yes |

### AJAX 핸들러 (`/ajax/`)
| 엔드포인트 | 기능 | 인증 필요 |
|-----------|------|----------|
| `/ajax/money_rank.php` | 충전/환전 실시간 랭킹 | **No** |
| `/ajax/callapi.php` | 카지노 API 프록시 | Yes |
| `/ajax/call_cw.php` | 코인 지갑 API | Yes |
| `/ajax/get_coupon_info.php` | 쿠폰 정보/사용 | Yes |
| `/ajax/get_user_hide_info.php` | 사용자 개인정보 (전화번호, 계좌) | Yes |
| `/ajax/get_pr_top_area.php` | 포인트/롤링 영역 | Yes |
| `/ajax/get_casino_roll_point_info.php` | 카지노 롤링 포인트 정보 | Yes |
| `/ajax/popup_deposit.php` | 충전 팝업 | Yes |
| `/ajax/popup_coin_deposit.php` | 코인 충전 팝업 | Yes |
| `/ajax/popup_withdraw.php` | 환전 팝업 | Yes |
| `/ajax/popup_withdraw_transfer.php` | 코인 환전 팝업 | Yes |
| `/ajax/popup_casino.php` | 카지노 머니 관리 | Yes |
| `/ajax/popup_casino_transfer.php` | 카지노 이체 | Yes |
| `/ajax/popup_join.php` | 회원가입 팝업 | No |
| `/ajax/popup_mypage.php` | 마이페이지 팝업 | Yes |
| `/ajax/popup_board.php` | 게시판 팝업 | Yes |
| `/ajax/popup_event.php` | 이벤트 팝업 | Unknown |
| `/ajax/popup_notice.php` | 공지사항 팝업 | Unknown |
| `/ajax/popup_rules.php` | 이용규정 팝업 | Yes |
| `/ajax/popup_slot_*.php` | 각 슬롯 게임 팝업 | Yes |

### 페이지 엔드포인트
| 엔드포인트 | 기능 |
|-----------|------|
| `/join.php` | 회원가입 (Cloudflare Challenge 보호) |
| `/join_usdt.php` | 테더(USDT) 회원가입 |
| `/money_manage.php` | 카지노 머니 관리 |
| `/money_manage_sp.php` | 스포츠 머니 관리 |
| `/coupon.php` | 쿠폰 |
| `/mypage.php` | 마이페이지 |
| `/point.php` | 포인트 |
| `/point_rolling.php` | 롤링 포인트 |
| `/partner.php` | 파트너 |
| `/helpdesk.php` | 고객센터 |
| `/board.php`, `/board-read.php` | 게시판 |
| `/event.php`, `/event-read.php` | 이벤트 |
| `/notice.php`, `/notice-read.php` | 공지사항 |
| `/refer-list.php` | 지인추천 내역 |
| `/money_refer.php` | 추천 머니 |
| `/history-hammer.php` | 배팅 내역 |
| `/result-hammer.php` | 경기 결과 |
| `/logout.php` | 로그아웃 |

### 카지노/슬롯 엔드포인트
| 엔드포인트 | 기능 |
|-----------|------|
| `/casino/slot/mg.php?game=` | 마이크로 슬롯 |
| `/casino/slot/mg_demo.php?game=` | 마이크로 데모 |
| `/casino/slot/mg_demo_free.php?game=` | 마이크로 무료 데모 |
| `/casino/slot/ev.php?game=` | 에볼루션 슬롯 |
| `/casino/slot/qt.php?game=` | 큐테크 슬롯 |
| `/casino/slot_v2/pr.php?game=` | 프라그마틱 슬롯 v2 |
| `/casino/slot/ag.php?game=` | AG 슬롯 |
| `/casino/slot/hb.php` | 하바네로 슬롯 |
| `/casino/slot/hb_demo.php` | 하바네로 데모 |
| `/casino-pr.php` | 프라그마틱 카지노 |
| `/casino-mg.php` | 마이크로 카지노 |
| `/casino-ab.php` | ALLBET 카지노 |
| `/casino-ag.php` | AG 카지노 |
| `/casino-eg.php` | 에볼루션 카지노 |
| `/sports-sbo.php` | 스보벳 스포츠 |
| `/sports-bti.php` | BTi 스포츠 |
| `/sports-pinnacle.php` | 피나클 스포츠 |

---

## 4. 쿠키 분석

| 쿠키명 | 용도 | HttpOnly | Secure | SameSite | 만료 |
|--------|------|----------|--------|----------|------|
| `PHPSESSID` | 세션 관리 | **없음** | **없음** | **없음** | 세션 |
| `UUID` | 사용자 추적 | **없음** | **없음** | **없음** | 1년 |
| `pop` | 인트로 영상 쿠키 | **없음** | **없음** | **없음** | 1일 |
| `notice_*` | 팝업 공지 쿠키 | **없음** | **없음** | **없음** | 당일 |

---

## 5. HTTP 응답 헤더 분석

### 존재하는 보안 헤더
| 헤더 | 값 | 평가 |
|------|-----|------|
| `X-Frame-Options` | SAMEORIGIN | 양호 (Cloudflare 기본값) |
| `Referrer-Policy` | same-origin | 양호 (Cloudflare 차단 페이지에서만) |
| `Cache-Control` | no-store, no-cache, must-revalidate | 양호 |

### 누락된 보안 헤더
| 헤더 | 상태 | 권장값 |
|------|------|--------|
| `Content-Security-Policy` | **누락** | `default-src 'self'; script-src 'self' cdnjs.cloudflare.com ...` |
| `X-Content-Type-Options` | **누락** | `nosniff` |
| `Strict-Transport-Security` | **누락** | `max-age=31536000; includeSubDomains` |
| `Permissions-Policy` | **누락** | 적절히 설정 필요 |

---

## 6. 취약점 요약 및 우선순위

| 우선순위 | ID | 취약점 | OWASP 분류 |
|----------|------|--------|----------|
| 1 | C-01 | `eval()` 코드 인젝션 | A03:2021 Injection |
| 2 | C-02 | CSRF 토큰 부재 | A01:2021 Broken Access Control |
| 3 | C-03 | 비밀번호 평문 노출 | A02:2021 Cryptographic Failures |
| 4 | C-04 | `.git` 디렉터리 노출 | A01:2021 Broken Access Control |
| 5 | C-05 | `.env` 파일 노출 | A05:2021 Security Misconfiguration |
| 6 | H-01 | jQuery XSS 취약점 | A06:2021 Vulnerable Components |
| 7 | H-02 | 서버 응답 XSS | A03:2021 Injection |
| 8 | H-03 | 쿠키 보안 미흡 | A05:2021 Security Misconfiguration |
| 9 | H-04 | URL 파라미터 인젝션 | A03:2021 Injection |
| 10 | H-05 | 문자열 연결 인젝션 | A03:2021 Injection |
| 11 | H-06 | 보안코드 비활성화 | A07:2021 Auth Failures |
| 12 | M-01 | 비인증 정보 노출 | A01:2021 Broken Access Control |
| 13 | M-02~03 | 보안 헤더 누락 | A05:2021 Security Misconfiguration |
| 14 | M-05 | moment.js 취약점 | A06:2021 Vulnerable Components |
| 15 | M-06~07 | 서버 오류/경로 노출 | A05:2021 Security Misconfiguration |

---

## 7. 화이트박스 테스트 시 중점 확인 사항

소스코드 업로드 후 아래 항목을 우선적으로 점검할 예정:

1. **SQL Injection**: 모든 PHP 파일의 DB 쿼리에서 파라미터 바인딩 여부
2. **세션 관리**: 세션 고정, 세션 하이재킹 방어 코드 확인
3. **파일 업로드**: 파일 업로드 기능 존재 시 검증 로직
4. **인증/인가**: 각 엔드포인트의 로그인 검증 및 권한 체크 일관성
5. **비밀번호 저장**: 해시 알고리즘 (bcrypt/argon2 vs MD5/SHA1)
6. **API 프록시**: `/ajax/callapi.php`의 외부 API 호출 시 인증 정보 관리
7. **코인 지갑**: `/ajax/call_cw.php`의 금융 거래 검증 로직
8. **관리자 패널**: admin 관련 파일 및 접근 제어
9. **서버 설정**: `.htaccess`, `php.ini` 보안 설정
10. **데이터베이스 스키마**: 민감정보 암호화 여부

---

## 8. 즉시 조치 권장 사항

### 긴급 (24시간 이내)
1. `.git`, `.env` 파일을 웹 서버 document root에서 제거 또는 `.htaccess`로 완전 차단
2. 모든 form과 AJAX 요청에 CSRF 토큰 추가
3. `eval()` 호출을 `JSON.parse()`로 대체

### 단기 (1주 이내)
4. jQuery를 3.7.x 이상으로 업그레이드
5. moment.js를 dayjs 또는 date-fns로 교체
6. 쿠키에 `HttpOnly`, `Secure`, `SameSite=Strict` 플래그 추가
7. CSP, HSTS, X-Content-Type-Options 헤더 추가
8. 로그인 보안코드(캡차) 재활성화
9. `/ajax/money_rank.php`에 인증 추가

### 중기 (1개월 이내)
10. 모든 사용자 입력에 대한 서버사이드 검증 및 이스케이핑 구현
11. 커뮤니티 바인딩 비밀번호 노출 제거
12. Flash 레거시 코드 제거
13. phpMyAdmin 접근 완전 차단 또는 제거
