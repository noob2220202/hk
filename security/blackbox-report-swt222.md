# swt-222.com 블랙박스 보안 점검 리포트

- **대상(Target):** `https://swt-222.com/` (스위트 카지노)
- **점검 유형:** 블랙박스(외부 관찰) — 소스코드 미열람 상태
- **권한(Authorization):** 사이트 소유자/운영자 본인이 점검을 요청·승인 (self-owned)
- **원칙:** 비파괴(non-destructive)·저볼륨 요청만 사용. DoS/대량요청/브루트포스/데이터변조 미수행
- **작성일:** 2026-10-04 (2차 심화 분석 반영)
- **다음 단계:** 화이트박스(소스코드) 확보 후 각 항목의 실제 원인 확인 및 수정 가이드 제공

> **2차 심화 분석 업데이트:** 내부 JSP include·레거시 JS·엔드포인트 라우팅을 추가로 분석하여
> **F-16 ~ F-22**(쿠키 기반 DOM XSS, 조각 JSP 미인증 노출, 파일 업로드 표면, 공격자 제어 iframe,
> 레거시 jQuery 혼용, 인가 게이트 동작)를 추가했습니다. 공격 표면 인벤토리도 확장되었습니다(§2-B, §3).

> 이 리포트는 "외부에서 관찰 가능한 표면"에 대한 것입니다. 아래 다수 항목은 **잠재 취약점 후보**이며,
> 실제 익스플로잇 가능 여부는 화이트박스 단계에서 코드로 확정합니다.

---

## 0. 환경 관련 유의사항 (관측 한계)

- 대상은 **WAF/CDN 없이 직접 노출**되어 있습니다. dw-04.com과 달리 Cloudflare 등 앞단 보호 계층이 관측되지 않아, 오리진 서버가 직접 인터넷에 노출됩니다.
- `www.swt-222.com`과 `swt-222.com`은 **서로 다른 서비스**를 반환합니다: `www`는 IIS 기본 페이지(703B), 루트 도메인은 실제 카지노 앱(282KB). 이는 구성 오류이며 정보 노출입니다.
- 본 점검 실행 환경은 **송신 TLS를 프록시가 종단**하므로, 실제 서버 인증서/암호군/TLS 버전은 이 환경에서 신뢰성 있게 판별할 수 없습니다. → **TLS 구성은 외부 도구(SSL Labs 등)로 별도 확인 필요.**
- 능동 탐침은 **엔드포인트당 단발성**으로 최소화했으며, 브루트포스·쿠키 탈취·자금 관련 동작·작동하는 XSS 실행 페이로드는 수행하지 않았습니다.

---

## 1. 기술 스택 지문 (Fingerprint)

| 항목 | 관측값 | 근거 |
|---|---|---|
| 웹서버 | **Microsoft IIS 10.0** | `server: Microsoft-IIS/10.0` |
| 백엔드 | **Java (Spring/Tomcat 추정)** | `Set-Cookie: JSESSIONID=...`, `/common/loginChk` REST 패턴, JSON 응답 구조 |
| 런타임 | **ASP.NET 호환 레이어** | `x-powered-by: ASP.NET` (IIS 역방향 프록시 가능) |
| 프론트 | jQuery 3.7.1, Tailwind CSS, Swiper 11 | `jquery-3.7.1.min.js`, `index.global.js`(Tailwind), `swiper-bundle.min.js` |
| 실시간 | **Socket.IO 4.8.1** | `cdn.socket.io/4.8.1/socket.io.min.js` |
| 서드파티 | Flaticon, Google Fonts, jsDelivr | CDN 참조 |
| WAF/CDN | **없음** (직접 노출) | 관련 헤더 부재 |
| 커스텀 헤더 | `x-blocked-user-agent: 0` | 자체 UA 필터 존재 |

---

## 2. 발견 사항 (Findings)

심각도는 CVSS 정성 기준(블랙박스 관측 기반 추정치)입니다. 확정은 화이트박스에서.

### 🟥 F-01 (Critical, 확정) postMessage XSS — origin 검증 미적용 + DOM 삽입

`/js/script.js`의 `window.addEventListener('message', ...)` 핸들러에서 **origin 검증이 주석 처리**되어 있으며, 수신된 데이터를 **`.html()`로 DOM에 직접 삽입**합니다.

```js
window.addEventListener('message', function(event) {
    // if (event.origin !== 'YOUR_ORIGIN') return;  ← 주석 처리됨!
    
    if (event.data.type === 'readNotice') {
        const {subject, contents} = event.data.dataId;
        $('#notice-detail').html(contents);   // ← 임의 HTML 삽입
    }
    if (event.data.type === 'readEvent') {
        const {subject, contents} = event.data.dataId;
        $('#event-detail').html('<img src="'+contents+'" ...>');  // ← img src 주입
    }
});
```

- **공격 시나리오:** 공격자가 `<iframe src="https://swt-222.com/">`으로 사이트를 프레이밍한 뒤, `iframe.contentWindow.postMessage({type:'readNotice', dataId:{subject:'x', contents:'<img src=x onerror=alert(document.cookie)>'}}, '*')` 전송 → 피해자 브라우저에서 **임의 스크립트 실행**.
- `readEvent`의 `contents`도 `<img src="` 뒤에 인코딩 없이 삽입 → `" onerror=...` 형태로 XSS 가능.
- **X-Frame-Options / CSP frame-ancestors 없음**(F-05)과 결합해 **클릭재킹 + XSS 체인** 가능.
- **연쇄(Chain):** F-01(postMessage XSS) + F-03(JSESSIONID Secure/SameSite 미설정) → 세션 탈취 → **계정 탈취**. 카지노 특성상 자금 직결.
- **근본 원인/해결:** `event.origin` 허용목록 검증 필수. `contents`를 `.html()`이 아닌 `.text()` 또는 DOMPurify로 무해화. `X-Frame-Options: SAMEORIGIN` 또는 CSP `frame-ancestors 'self'` 적용.

### 🟥 F-02 (Critical, 확정) 서버 오류 응답을 DOM에 직접 삽입 — 광범위 XSS 싱크

`/js/pub.js`의 `fn_page()`, `fn_pfPage()`, `fn_pfPageLoad__()` 등 **다수 함수**가 AJAX 500 오류 시 **`e.responseText`를 `$('#container').html()`로 직접 삽입**합니다.

```js
function fn_page(url){
    $.ajax({
        url: url,
        dataType:"text",
        success: function(result) {
            $('#container').html(result);       // 성공 응답도 인코딩 없이 삽입
        },
        error: function(e) {
            if (e.status == 500) {
                $('#container').html(e.responseText);  // 오류 응답 전체를 DOM에 삽입!
            }
        }
    });
}
```

- **관측된 인스턴스:** `pub.js` 내 `.html(e.responseText)` — **최소 4곳**, `.html(result)` — **최소 5곳**.
- 서버 500 오류에 사용자 입력이 반영(reflected)되면 즉시 반사형 XSS. 정상 응답에 저장형 데이터가 HTML로 오면 저장형 XSS.
- `fn_page(url)`의 `url` 파라미터가 클라이언트에서 제어되면 **임의 경로 로드 → XSS/오픈 리다이렉트**.
- **화이트박스 확인 필수:** 서버 오류 응답에 사용자 입력이 반영되는 엔드포인트 식별, `fn_page` 호출 시 URL이 어디서 오는지.

### 🔴 F-03 (High) 세션 쿠키 보안 플래그 부분 누락

관측된 `Set-Cookie`:

```
Set-Cookie: JSESSIONID=73F2758767...B0E5.user; Path=/; HttpOnly
```

- `HttpOnly` ✅ — XSS 시 `document.cookie`로 직접 탈취는 차단. (dw-04.com보다 양호)
- `Secure` **없음** → HTTP(평문) 접속 시 쿠키 노출. F-04(HTTP→HTTPS 미리다이렉트)와 결합 시 **세션 가로채기 가능**.
- `SameSite` **없음** → CSRF 방어 계층 부재(브라우저 기본값 `Lax` 의존이나 명시적 설정 권장).
- 쿠키 이름 `JSESSIONID`에 `.user` suffix → 톰캣 인스턴스 식별자 노출(jvmRoute). 내부 아키텍처 정보.

### 🔴 F-04 (High) HTTP→HTTPS 리다이렉트 없음 + HSTS 미설정

```
HTTP(80): HTTP/1.1 200 OK   ← 리다이렉트 없이 직접 응답!
```

- **HTTP(포트 80)에서 HTTPS로 301 리다이렉트가 없음.** HTTP 접속 시 **평문 통신** 상태로 콘텐츠 제공.
- `Strict-Transport-Security` 헤더 **모든 응답에 없음**.
- 카페/공용 Wi-Fi 등에서 **중간자 공격(MITM)** 시 로그인 자격증명·세션·금전 데이터 모두 평문 노출.
- dw-04.com은 최소한 301 리다이렉트는 있었으나, 이 사이트는 그마저 없어 **위험도 상향**.

### 🔴 F-05 (High) 보안 헤더 전면 부재 + 클릭재킹

앱의 정상 `200` 응답에 다음이 **모두 없음**:

| 헤더 | 상태 | 영향 |
|---|---|---|
| `Content-Security-Policy` | 없음 | XSS 완화 계층 부재. F-01/F-02와 결합 시 위험 극대 |
| `X-Content-Type-Options` | 없음 | MIME 스니핑 |
| `X-Frame-Options` | 없음 | **클릭재킹** 가능. F-01(postMessage XSS)의 전제조건 |
| `Referrer-Policy` | 없음 | 리퍼러 누출 |
| `Permissions-Policy` | 없음 | 불필요 기능 미제한 |

- `X-Frame-Options` 없음은 F-01과 직접 결합 → **iframe에 사이트 삽입 후 postMessage로 XSS 트리거** 가능.

### 🔴 F-06 (High) RSA 공개키 미인증 노출 + 로그인 아키텍처 취약점

로그인 전 호출되는 `/common/_enc_get` 엔드포인트가 **인증 없이** RSA 공개키를 반환합니다:

```json
{"header":{"code":"200","message":"OK"},
 "body":{"publicKeyModulus":"c5aad4d6b74a082ed30e291de40ff7d2...","publicKeyExponent":"14282"}}
```

- 키 모듈러스가 **64헥스 = 256비트**(32바이트)로 매우 짧음. 현대 RSA 최소 기준(2048비트)에 비해 **극도로 취약**하며 수초 내 인수분해 가능.
- 키쌍이 **요청마다 동일**한지, 또는 동적 생성인지 화이트박스에서 확인 필요. 동일하면 비밀키 복구 → 모든 로그인 자격증명 복호화 가능.
- `publicKeyExponent`가 `14282`(짝수) — 표준 RSA에서 지수는 홀수여야 함. 비표준 구현이거나 다른 암호체계일 가능성.
- **실질적 보호 효과가 거의 없는 클라이언트측 암호화**. TLS가 전송 보호를 담당해야 하며, 클라이언트측 RSA는 보완책에 불과.
- **화이트박스 최우선:** 서버측 비밀키 관리, 키 길이, 비밀번호 복호 후 처리(해시 저장 여부).

### 🟠 F-07 (Medium) CSRF 방어 부재 — 전체 폼/AJAX

- 모든 관측된 POST 폼과 AJAX 호출에 **CSRF 토큰이 없음**. 히든 필드 중 토큰 관련 항목 0개.
- `SameSite` 쿠키도 미설정(F-03) → **Cross-Site Request Forgery** 가능성 높음.
- 특히 위험한 엔드포인트:
  - `/common/changePoint` — 포인트→머니 전환(금전)
  - `/common/_transferCasinoAjax` — 카지노 자금 전환(금전)
  - `/_r_code` — 회원가입
  - `/common/loginChk` — 로그인(Login CSRF)
- **화이트박스 확인:** 서버측에서 별도 CSRF 검증(Spring Security CSRF filter 등)이 있는지.

### 🟠 F-08 (Medium) 보안코드(캡차) 비활성화 — PC 로그인

`/js/login.js`에 보안코드 검증이 **주석 처리**되어 비활성:

```js
// check = $("#login-code");
// if (!check.val()) {
//     alert("보안코드를 입력해 주세요.");
//     check.focus();
//     return;
// }
```

- **PC 로그인** (`login_precheck`)은 캡차 검증 없음 → 브루트포스/크리덴셜 스터핑 노출.
- **모바일 로그인** (`login_precheck_m`)은 보안코드 검증 활성화 → **불일치** (PC만 우회 가능).
- **긍정적 관측:** 로그인 실패 응답이 일반 메시지("아이디 또는 비밀번호가 잘못되었습니다.")로, **사용자 열거(user enumeration) 미유발**. 양호.

### 🟠 F-09 (Medium) www 서브도메인에 IIS 기본 페이지 노출

`https://www.swt-222.com/` 접속 시 **IIS 기본 시작 페이지**(Welcome page)가 그대로 반환됩니다:

```html
<title>IIS Windows Server</title>
<a href="http://go.microsoft.com/fwlink/?linkid=66138&clcid=0x409">
    <img src="iisstart.png" alt="IIS" width="960" height="600" />
</a>
```

- 웹서버 종류·버전·OS가 명시적으로 드러남(정보수집 활용).
- 사용자가 `www.swt-222.com`에 접속해도 실제 서비스로 리다이렉트되지 않음(운영 결함).
- **수정:** `www` → 루트 도메인으로 301 리다이렉트 설정, 또는 동일 앱 바인딩.

### 🟠 F-10 (Medium) 외부 스크립트 SRI(무결성) 미적용 — 공급망 위험

`integrity=` 속성 **0개**. 외부 CDN에서 직접 로드:

```
https://code.jquery.com/jquery-3.7.1.min.js
https://cdn.jsdelivr.net/npm/swiper@11/swiper-bundle.min.js
https://cdn.socket.io/4.8.1/socket.io.min.js
https://cdn.jsdelivr.net/npm/jquery-validation@1.19.5/dist/jquery.validate.min.js
https://cdn.jsdelivr.net/npm/@flaticon/flaticon-uicons@3.3.1/css/all/all.min.css
https://cdn-uicons.flaticon.com/2.6.0/... (CSS 2건)
```

- 외부 CDN이 변조/탈취되면 임의 스크립트가 사용자 브라우저(로그인 세션 컨텍스트)에서 실행.
- 특히 **Socket.IO** 라이브러리 변조 시 실시간 통신 전체 장악 가능.
- → `integrity`+`crossorigin` 또는 자가호스팅 권장.

### 🟠 F-11 (Medium) 서버 정보 헤더 노출

모든 응답에 서버 식별 헤더가 포함됩니다:

```
server: Microsoft-IIS/10.0
x-powered-by: ASP.NET
x-blocked-user-agent: 0
```

- IIS 버전, ASP.NET 프레임워크가 명시적으로 노출 → 버전 특정 취약점 검색 용이.
- `x-blocked-user-agent: 0` → 자체 UA 차단 로직 존재 여부가 외부에서 관측됨.
- **수정:** 응답에서 `server`, `x-powered-by` 제거 또는 일반화. 커스텀 헤더 제거.

### 🟠 F-12 (Medium) `postMessage` wildcard origin 전송

`script.js`에서 iframe에 메시지를 보낼 때 **targetOrigin이 `'*'`**(와일드카드)입니다:

```js
iframe.contentWindow.postMessage({
    type: 'command',
    action: 'reset-input'
}, '*');   // ← 모든 origin에게 메시지 전송
```

- iframe 내 페이지가 다른 origin으로 네비게이트된 경우에도 **민감한 커맨드 데이터**가 전달.
- 입출금(withdraw/deposit) iframe에 `'*'` origin으로 커맨드 전송 → 공격자가 iframe을 장악하면 명령 수신 가능.
- **수정:** targetOrigin을 명시적 origin(`https://swt-222.com`)으로 지정.

### 🟡 F-13 (Low) 회원가입 시 민감 정보 수집 — 보호 미비

회원가입 폼(`/_r_code`, `mode=joinok2`)이 **CSRF 토큰 없이** 다음을 수집합니다:

- 아이디, 비밀번호, 닉네임
- **생년월일**, **통신사**, **휴대폰 번호**
- **은행명**, **계좌번호**, **예금주명**
- **출금 비밀번호**
- 가입코드

무기명 회원가입(`mode=joinok3`)도 별도 존재하며, **암호화폐 지갑 주소**까지 수집.

- 이 데이터가 HTTPS 없이(F-04) 전송되면 **은행 계좌·개인정보 평문 노출**.
- CSRF(F-07) 결합 시 **위조 가입 가능성**.
- **중복 확인 비활성화:** 아이디/닉네임 중복 확인 버튼이 주석 처리되어 있음.

### 🟡 F-14 (Low/Info) 디버그 코드 잔존

- `console.log("Fuck");` 스타일의 디버그 코드 존재 여부는 화이트박스에서 확인 필요.
- `console.log("[DEBUG] getCallCasinoChip - 0 값 무시")` — 프로덕션에 디버그 로그 잔존 관측.
- 주석 처리된 코드 다수(`// alert(e.responseText)`, `//resetGame()` 등) → 코드 위생 관점 정리 필요.

### 🟡 F-15 (Info) `.env` 경로 302 리다이렉트

- `GET /.env` → `302` 리다이렉트(`/common/loginMove`). **404가 아닌 302** 응답은 해당 경로에 대해 앱 라우터가 처리하고 있음을 시사.
- `.env` 파일이 서버에 존재하나 인증 뒤에 숨겨져 있을 가능성. 화이트박스에서 확인 필요.
- `.DS_Store`도 동일 302 → 같은 라우팅 패턴.

---

## 2-B. 심화 점검 추가 발견 (2차 — 더 깊은 분석)

> 1차 리포트 이후 내부 JSP include·레거시 JS·엔드포인트 라우팅을 추가 분석하여 확정한 항목입니다.

### 🔴 F-16 (High, 확정) 쿠키 기반 DOM XSS — `gameImg` 쿠키 → `.html()`

내부 JSP `/common/inc/contentFavorites.jsp`(아래 F-17로 **미인증 직접 접근 가능**)의 `displayImages()` 함수가 **`gameImg` 쿠키를 `JSON.parse` 후 인코딩 없이 HTML로 조립·삽입**합니다.

```js
function getImagesFromCookie() {
    ...
    return JSON.parse(imagesString) || [];   // gameImg 쿠키 값을 그대로 파싱
}
function displayImages() {
    var images = getImagesFromCookie();
    images.forEach(function(image, index) {
        vHtml += '<img src="' + image.url + '" ...>';          // ← 인코딩 없음
        vHtml += '<h6 class="...">' + image.name + '</h6>';     // ← 인코딩 없음
    });
    $(".game_list_slot_area").html(vHtml);   // ← DOM 삽입
}
```

- `image.url`이 `<img src="...">` 안에, `image.name`이 `<h6>` 안에 **인코딩 없이** 삽입 → `image.url = 'x" onerror="alert(document.cookie)'` 형태로 **DOM 기반 XSS**.
- **쿠키 쓰기 프리미티브 확보 경로:** (1) F-01/F-02의 XSS로 쿠키 설정, (2) `Secure` 플래그 부재(F-03)+HTTP 평문(F-04)이라 **MITM이 `Set-Cookie`로 `gameImg` 주입**, (3) 서브도메인 장악 시 쿠키 토싱.
- `gameImg`에 `HttpOnly`가 없을 가능성이 높음(클라이언트 JS가 읽어야 하므로) → XSS 체인 강화.
- **근본 해결:** `.html()` 대신 `.text()`/DOM API 사용, 또는 DOMPurify. `image.url`은 URL 허용목록 검증.

### 🟠 F-17 (Medium, 확정) 내부 JSP include 파일 미인증 직접 접근

`/common/inc/contentFavorites.jsp`가 **로그인 없이 `200`으로 직접 접근**되어 클라이언트 로직과 내부 엔드포인트가 노출됩니다.

```
GET /common/inc/contentFavorites.jsp  →  200 (본문 8KB, 인증 불필요)
GET /common/inc/header.jsp 등 기타    →  404
```

- 이 파일을 통해 비공개 엔드포인트 `/wca/slotPlay`, `/wca/_gameVendorCasinoAjax`가 노출됨.
- 본래 인증된 탭 로드 흐름에서만 포함(include)되어야 할 조각 페이지가 직접 라우팅으로 노출된 **구성 오류**. 다른 `inc` 파일은 404이므로 이 파일만 라우팅에 노출된 것으로 추정.
- **수정:** `/common/inc/` 이하 조각 JSP는 포워드 전용으로 제한(직접 URL 접근 차단).

### 🟠 F-18 (Medium/High, 화이트박스) 파일 업로드 엔드포인트 — `/slab/cmm/common/imgFileUpload`

`fuc_common.js`의 `imgFileUpload()`/`imgFileUpload2()`가 `multipart/form-data`로 이미지를 업로드합니다.

```js
$("#frm1").ajaxForm({
    url: "/slab/cmm/common/imgFileUpload",
    enctype: "multipart/form-data",
    dataType: "text",
    success: function(data){ if(data=="DENY"){...} else { $("#uploadImgName").val(data); } }
});
```

- 엔드포인트 실재 확인: `POST /slab/cmm/common/imgFileUpload` → `405`(메서드 허용 안됨, 즉 경로 존재).
- `/slab/cmm/` 네임스페이스는 별도 레거시/백오피스 프레임워크로 추정. 업로드가 **인증을 요구하는지, 확장자/콘텐츠타입/경로/크기 검증이 있는지 화이트박스 최우선 확인**.
- 위험: **웹쉘 업로드(.jsp/.asp)**, 경로 순회(`../`), SVG/HTML 통한 저장형 XSS, 파일명 인젝션. IIS+Tomcat 혼합 환경이라 이중확장자(`.jsp;.jpg`) 등 우회 표면 넓음.

### 🟠 F-19 (Medium) 공격자 제어 iframe `src` — 미니게임 탭(tab203)

`contentFavorites.jsp`의 `loadRecentGame()`은 쿠키에서 온 `game.gameUrl`을 **검증 없이 iframe `src`로 지정**합니다.

```js
$('#tab203 iframe').attr('src', game.gameUrl);   // gameUrl = 쿠키 유래
```

- `gameUrl`이 쿠키(`gameImg`) 유래이므로 F-16과 동일한 쓰기 경로로 **임의 iframe 네비게이션**(피싱/오버레이) 가능.
- 카지노 게임은 새 창으로 `window.open(data.data.url, ...)`도 수행 → 서버가 내려주는 URL의 출처/검증(오픈 리다이렉트·SSRF)도 화이트박스 확인.

### 🟡 F-20 (Low) 레거시 jQuery/플러그인 혼용 — EOL 버전

프론트엔드 라이브러리 버전이 페이지별로 **불일치**합니다.

- 메인 앱: jQuery **3.7.1** (현행, 양호).
- `/common/loginMove` 및 레거시 페이지: **jQuery 1.11.3** (2015년, EOL) 직접 로드 (`/js/jquery-1.11.3.min.js`).
- `/js/jquery.cookie.js` → **v1.1** (현행 1.4.x 대비 매우 구버전).
- EOL jQuery는 알려진 XSS/프로토타입 이슈에 노출. 레거시 페이지가 인증 영역에서 쓰이면 위험 전이.

### 🟡 F-21 (Info) Tailwind CSS v4 브라우저 런타임 컴파일 (프로덕션)

- `/js/index.global.js`는 **Tailwind CSS 브라우저 빌드 v4.0.14**(런타임 CSS 컴파일러)입니다.
- 프로덕션에서 브라우저측 CSS 컴파일은 성능 저하 + 전체 유틸리티 엔진 노출. 빌드타임 CSS로 전환 권장(기능상 취약점은 아님).

### 🟢 F-22 (긍정적 관측) 주요 기능 엔드포인트에 인가 게이트 존재

- `/wca/slot2`, `/wca/live2`, `/sports/`, `/wsports/`, `/game/inplay`, `/bbs/event` 등 게임/보드 엔드포인트는 **미인증 시 `302 → /common/loginMove`**로 차단됨.
- dw-04.com의 미인증 랭킹 노출(F-11)과 달리 **기본 인가 게이트가 동작**. 다만 `/common/inc/contentFavorites.jsp`(F-17)와 `/_r_code (mode=bank)`는 예외로 노출됨.
- **화이트박스 확인:** 인가가 라우팅 레벨인지 핸들러 레벨인지, 우회 가능한 경로(대소문자·인코딩·세미콜론 `;jsessionid`)가 있는지.

---

## 3. 공격 표면 인벤토리 (화이트박스 대상 엔드포인트)

HTML/JS에서 식별된 서버 엔드포인트 — 화이트박스에서 입력검증/권한/쿼리를 집중 리뷰:

| 엔드포인트 | HTTP | 성격 | 우선 점검 항목 |
|---|---|---|---|
| `/common/loginChk` | POST | 로그인 처리 | SQLi, 레이트리밋, 세션재생성, CSRF, RSA 복호 |
| `/common/_enc_get` | POST | RSA 공개키 발급(**미인증**) | 키 길이/재사용, 비표준 지수 |
| `/common/logout` | POST | 로그아웃 | 세션 무효화 |
| `/common/balanceAjax` | POST | 잔액 조회(5초 폴링) | 인증확인, IDOR(타인 잔액) |
| `/common/changePoint` | POST | 포인트/콤프→머니 전환 | **CSRF, 인가, 금액변조, 경쟁조건** |
| `/common/_transferCasinoAjax` | POST | 카지노 자금 전환(seqKey) | **CSRF, 인가, 금액변조, IDOR, 경쟁조건** |
| `/common/betwinAjax` | POST | 베팅 승리 기록 조회 | 정보노출, 인증 |
| `/_r_code` (mode=joinok2) | POST | 회원가입 | CSRF, 중복검사 우회, 인젝션, 레이트리밋 |
| `/_r_code` (mode=joinok3) | POST | 무기명 회원가입 | 동일 |
| `/_r_code` (mode=bank) | POST | 은행 목록 조회(**미인증**) | 정보성(양호) |
| `/wca/_gameVendorLobbyAjax` | POST | 게임 벤더 로비 | 인증확인, SSRF, 파라미터변조 |
| `/wca/_gameSlotListAjax` | POST | 슬롯 목록 | 인증확인, 인젝션 |
| `/wca/_gameUserChipBalanceAjax` | POST | 카지노 칩 잔액 | 인증확인, IDOR |
| `/dca/_gameUserChipBalanceAjax` | POST | 칩 잔액(다른 경로) | 동일 |
| `/casino3/_gameVendorLobbyAjax` | POST | 게임 로비(v3) | SSRF, 인가 |
| `/slab/cmm/common/imgFileUpload` | POST | **파일 업로드**(multipart) | **웹쉘/확장자·경로검증, 인증(F-18)** |
| `/wca/slotPlay` | POST | 슬롯 게임 실행(.load) | 인증, 반영형 HTML/XSS |
| `/wca/_gameVendorCasinoAjax` | POST | 카지노 게임 URL 발급 | SSRF, 오픈리다이렉트, 인가 |
| `/wca/slot2?vendorKey=` | GET | 슬롯 페이지(.load, 인증) | `vendorKey` 반영/인젝션 |
| `/wca/live2` | GET | 라이브 카지노(인증) | 인가 |
| `/sports/` `/wsports/?type=` | GET | 스포츠북(인증) | `type` 반영, 인가 |
| `/game/inplay` | GET | 인플레이(인증) | 인가 |
| `/bbs/event?seq=&type=` | GET→iframe | 이벤트/공지 상세(인증) | **SQLi/IDOR(`seq`)**, 반영형 XSS |
| `/common/inc/contentFavorites.jsp` | GET | 즐겨찾기 조각(**미인증 노출**) | **쿠키 DOM XSS(F-16), 노출(F-17)** |
| `/common/statistical` | POST | 접속 통계 수집 | 인증, 저장형 처리 |
| `/ia/member/logout` | POST | 레거시 로그아웃 | 세션 무효화 |

> 카지노/스포츠 도메인 특성상 **금전 로직**(입출금, 포인트/롤링, 쿠폰, 베팅 정산)이 최우선 리뷰 대상입니다: 금액/수량 **서버측 재검증**, **원자적 트랜잭션**, **IDOR**(타인 계정 자금 접근), **경쟁조건(race condition)**(중복 출금/베팅), **음수/오버플로우**.

---

## 4. dw-04.com과의 비교

| 항목 | dw-04.com | swt-222.com | 비고 |
|---|---|---|---|
| WAF/CDN | Cloudflare (시그니처 기반) | **없음** | swt-222이 직접 노출, 위험 높음 |
| 백엔드 | PHP | Java (Spring/Tomcat 추정) | 기술 스택 상이 |
| HTTP→HTTPS | 301 리다이렉트 있음 | **리다이렉트 없음** | swt-222이 더 위험 |
| HttpOnly | **없음** (Critical) | **있음** (양호) | swt-222이 더 양호 |
| CSRF 토큰 | 없음 | 없음 | 동일 문제 |
| postMessage 취약점 | 미관측 | **확정 (Critical)** | swt-222 고유 |
| eval() 기반 처리 | 광범위 (ajax_call.js) | 미관측 | dw-04.com 고유 |
| 서버 오류→DOM 삽입 | 미관측 | **확정 (Critical)** | swt-222 고유 (pub.js) |
| RSA 키 노출 | 미관측 | **확정** | swt-222 고유 |
| 보안코드 비활성화 | 전체 주석 | PC만 주석 (모바일은 활성) | 부분 동일 |
| jQuery 버전 | 1.11.3 (EOL) | 메인 3.7.1 / 레거시 1.11.3 혼용 | swt-222 부분 양호 (F-20) |
| SRI | 0개 | 0개 | 동일 문제 |
| 쿠키 기반 DOM XSS | 미관측 | **확정 (F-16)** | swt-222 고유 (gameImg 쿠키) |
| 내부 조각 미인증 노출 | 민감경로 403(불명) | **확정 (F-17)** | contentFavorites.jsp |
| 파일 업로드 표면 | 미관측 | **확정 존재 (F-18)** | /slab/cmm/ imgFileUpload |
| 미인증 데이터 노출 | 랭킹 노출(F-11) | 대부분 인가 게이트(F-22) | swt-222이 양호 |

---

## 5. 화이트박스 단계 점검 계획 (소스 확보 후)

1. **postMessage XSS (F-01):** `readNotice`/`readEvent` 이벤트에서 `contents`가 서버 응답에서 오는지, 사용자 입력이 저장되는지 확인. iframe 구조/origin 관계 전체 매핑.
2. **서버 오류 XSS (F-02):** IIS/Tomcat의 500 오류 페이지가 요청 파라미터를 반영하는지 확인. 커스텀 에러 페이지 설정 여부.
3. **RSA 구현 (F-06):** 키 길이, 키 고정 여부, 서버측 복호 로직, 비밀번호 해시 저장 여부.
4. **인젝션:** `/common/loginChk`, `/_r_code` 등에서 PreparedStatement 사용 여부. Spring Data JPA면 기본 안전하나 네이티브 쿼리 확인.
5. **CSRF:** Spring Security CSRF filter 활성화 여부. 비활성이면 모든 상태변경 POST가 위험.
6. **인증/세션:** 로그인 성공 시 세션 재생성(`session.invalidate()` + 신규 생성), 로그아웃 시 완전 무효화.
7. **인가/IDOR:** `balanceAjax`, `_transferCasinoAjax` 등에서 사용자 식별이 세션에서 오는지 클라이언트 파라미터를 신뢰하는지. `seqKey`의 의미와 검증.
8. **금전 로직:** `changePoint`, `_transferCasinoAjax`의 트랜잭션 원자성, 경쟁조건(동시 요청으로 이중 전환), 음수/오버플로우.
9. **Socket.IO:** 인증 방식(토큰/세션), 이벤트 검증, 권한 분리. WebSocket hijacking 가능성. (연결 URL은 인증 후 로드되어 블랙박스 미확인)
10. **파일 업로드 (F-18):** `/slab/cmm/common/imgFileUpload` — 인증 요구 여부, 서버측 확장자 허용목록(블랙리스트 금지), 콘텐츠타입·매직바이트 검증, 저장 경로(웹루트 외부·실행권한 제거), 파일명 정규화(경로순회 차단), IIS/Tomcat 이중확장자·`;` 우회 대응.
11. **무기명 회원가입:** 자동 가입 남용 방지(레이트리밋, 캡차), 지갑 주소 검증.
12. **쿠키 DOM XSS (F-16):** `gameImg` 쿠키 생성 주체(서버/클라이언트), `HttpOnly`/`Secure` 설정, `image.url`/`image.name`/`gameUrl`의 출력 인코딩. `contentFavorites.jsp`의 `.html()` 싱크 전면 점검.
13. **조각 JSP 노출 (F-17):** `/common/inc/*` 직접 URL 접근 차단(포워드 전용), 라우팅/시큐리티 설정에서 include 조각이 핸들러로 노출되지 않는지.
14. **게시판 `seq` (F-16/인벤토리):** `/bbs/event?seq=`의 `seq`/`type`이 쿼리에 바인딩되는 방식(SQLi), 타 사용자 글 접근(IDOR).
15. **게임 URL 발급:** `/wca/_gameVendorCasinoAjax`·`fn_pfPageLoad`가 반환하는 `gameUrl`의 생성·검증(오픈 리다이렉트/SSRF), `window.open` 대상 제한.
16. **인가 우회 (F-22):** 인가 게이트가 라우팅/핸들러 어느 레벨인지, 대소문자·URL 인코딩·`;jsessionid`·경로 정규화 우회 가능성.

---

## 6. 즉시 적용 가능한 완화책 (코드 없이 인프라/설정 레벨)

화이트박스 이전에도 **IIS/서버 설정**만으로 리스크를 낮출 수 있는 항목:

### 긴급 (F-01 대응)
- **IIS에서 응답 보안 헤더 추가** (URL Rewrite 모듈 또는 web.config):
  - `X-Frame-Options: SAMEORIGIN` → postMessage XSS의 iframe 프레이밍 차단
  - `Content-Security-Policy: frame-ancestors 'self'` → 동일 효과 (CSP 방식)

### 높은 우선순위
- **HTTP→HTTPS 301 리다이렉트 설정** (IIS URL Rewrite):
  ```xml
  <rule name="HTTP to HTTPS" stopProcessing="true">
    <match url="(.*)" />
    <conditions><add input="{HTTPS}" pattern="off" /></conditions>
    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
  </rule>
  ```
- **HSTS 헤더 추가**: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- **쿠키 플래그**: Tomcat `server.xml`에서 `secure="true"`, `sameSite="Lax"` 설정
- **www 서브도메인**: IIS 바인딩에서 `www.swt-222.com` → `swt-222.com` 301 리다이렉트, 또는 동일 앱 바인딩. IIS 기본 페이지 제거.

### 보안 헤더 추가 (IIS web.config)
```xml
<httpProtocol>
  <customHeaders>
    <remove name="X-Powered-By" />
    <remove name="Server" />
    <add name="X-Content-Type-Options" value="nosniff" />
    <add name="X-Frame-Options" value="SAMEORIGIN" />
    <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
    <add name="Content-Security-Policy" value="frame-ancestors 'self'" />
  </customHeaders>
</httpProtocol>
```

### 기타
- **PC 로그인 캡차 재활성화** (login.js 주석 해제)
- **외부 스크립트 SRI 적용** 또는 자가호스팅
- `x-blocked-user-agent` 커스텀 헤더 제거
- 디버그 `console.log` 프로덕션에서 제거

---

## 7. 부록 — 재현용 관측 명령(비파괴)

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# 앱 실제 응답 헤더/쿠키 (루트 도메인)
curl -sS -D - -o /dev/null -A "$UA" https://swt-222.com/

# www 서브도메인 IIS 기본 페이지 확인
curl -sS -A "$UA" https://www.swt-222.com/

# HTTP 리다이렉트 미설정 확인
curl -sS -D - -o /dev/null -A "$UA" http://www.swt-222.com/

# 로그인 오류 응답 (사용자 열거 미유발 확인)
curl -sS -A "$UA" -X POST https://swt-222.com/common/loginChk \
  --data "mode=login&id=INVALID&pw=INVALID&captchaKey=&publicKeyExponent=&publicKeyModulus="

# F-06: RSA 공개키 미인증 노출
curl -sS -A "$UA" -X POST https://swt-222.com/common/_enc_get \
  --data "id=test&pw=test"

# postMessage XSS 코드 확인 (origin 검증 주석 처리)
curl -sS -A "$UA" https://swt-222.com/js/script.js | grep -A 3 "addEventListener.*message"

# pub.js의 responseText→DOM 삽입 패턴 확인
curl -sS -A "$UA" https://swt-222.com/js/pub.js | grep "html(e.responseText)"

# F-16/F-17: 내부 조각 JSP 미인증 노출 + 쿠키 DOM XSS 싱크 확인
curl -sS -o /dev/null -w "%{http_code}\n" -A "$UA" https://swt-222.com/common/inc/contentFavorites.jsp   # 200
curl -sS -A "$UA" https://swt-222.com/common/inc/contentFavorites.jsp | grep -E "getImagesFromCookie|game_list_slot_area"

# F-18: 파일 업로드 엔드포인트 실재 확인 (405 = 경로 존재, POST 전용)
curl -sS -o /dev/null -w "%{http_code}\n" -A "$UA" https://swt-222.com/slab/cmm/common/imgFileUpload

# F-20: 레거시 EOL jQuery 로드 확인
curl -sS -A "$UA" https://swt-222.com/common/loginMove | grep "jquery-1.11.3"

# F-22: 인가 게이트 동작 확인 (미인증 시 302 → loginMove)
for p in /wca/slot2 /wca/live2 /sports/ /game/inplay /bbs/event; do
  curl -sS -o /dev/null -w "%{http_code} %{redirect_url}  $p\n" -A "$UA" "https://swt-222.com$p"
done
```

---

*본 리포트는 소유자 승인 하에 수행된 블랙박스 점검 결과입니다. 실제 익스플로잇 여부·상세 수정안은 화이트박스(소스코드) 단계에서 확정합니다.*
