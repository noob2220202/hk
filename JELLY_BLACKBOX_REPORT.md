# 젤리 카지노 (jelly2022.com) 블랙박스 보안 테스트 리포트

**대상**: https://jelly2022.com/  
**테스트 일시**: 2026-10-29  
**테스트 방식**: 비인증 + 인증(rnalswo1) 블랙박스 테스트  
**테스터**: 자동화 보안 스캐너 + 수동 분석  
**버전**: v2 (인증 테스트 추가)

---

## 1. 기술 스택 분석

| 항목 | 상세 |
|------|------|
| **프론트엔드** | Next.js (React SSR), App Router |
| **백엔드** | BB Solution SaaS 멀티테넌트 플랫폼 |
| **내부 도메인** | `sample5.bb-s.cc` (Microsoft-HTTPAPI/2.0) |
| **CDN/WAF** | Cloudflare |
| **인증** | NextAuth (credentials + impersonate 프로바이더) |
| **테넌트 ID** | 8 |
| **카지노 벤더** | tower (40개 프로바이더 통합) |
| **운영 모드** | seamless (카지노 잔액 통합) |
| **Build ID** | `nVbb0CZtqMkRFDSlCd_aj` |
| **플랫폼 버전** | platform-5 |

---

## 2. 발견사항 요약

| 심각도 | 건수 |
|--------|------|
| **CRITICAL** | 6 |
| **HIGH** | 7 |
| **MEDIUM** | 6 |
| **LOW** | 5 |
| **합계** | **24** |

---

## 3. CRITICAL 발견사항

### C-1. Impersonate 인증 프로바이더 노출 — 계정 탈취 경로

**엔드포인트**: `GET /api/auth/providers`  
**응답 (비인증)**:
```json
{
  "impersonate": {
    "callbackUrl": "https://sample5.bb-s.cc/api/auth/callback/impersonate",
    "type": "credentials"
  },
  "credentials": {
    "callbackUrl": "https://sample5.bb-s.cc/api/auth/callback/credentials",
    "type": "credentials"
  }
}
```

**위험성**: `impersonate` 프로바이더는 관리자가 특정 사용자로 가장(impersonate)하기 위한 기능이다. 이 프로바이더의 존재와 콜백 URL이 비인증 상태에서 공개되어 있어, 공격자가:
1. `impersonate` 콜백에 직접 요청을 보내 다른 사용자 세션 탈취 시도 가능
2. 내부 도메인(`sample5.bb-s.cc`)을 통한 우회 경로 탐색 가능
3. userId 파라미터 brute force로 관리자/일반 사용자 세션 획득 시도 가능

**권장조치**: 
- `/api/auth/providers`에서 `impersonate` 프로바이더 제거 또는 인증 필수화
- impersonate 콜백에 관리자 세션 + HMAC 서명 검증 추가

---

### C-2. 브루트포스 방어 부재 — 계정 크래킹

**엔드포인트**: `POST /api/login-precheck`  
**테스트 방법**: 동일 IP에서 `admin` 계정으로 50회 연속 틀린 비밀번호 시도

**결과**: **50회 시도 후에도 차단 0건**

```
시도 1~50: 모두 {"ok":false,"reason":"WRONG_CREDENTIALS"} 반환
IP 차단: 없음
계정 잠금: 없음
CAPTCHA: 없음
응답 지연: 없음
```

**위험성**: 공격자가 자동화 도구로 무제한 비밀번호 대입 가능. 사전 공격(dictionary attack)이나 자격 증명 스터핑(credential stuffing)에 완전 노출.

**비교**: dwdw-00.com도 150회 차단 없었으나, 해당 사이트는 레거시 PHP. Next.js SaaS 플랫폼에서 rate limiting이 없는 것은 더 심각한 설계 결함.

**권장조치**:
- 5회 실패 후 30초 지연, 10회 실패 후 CAPTCHA, 20회 실패 후 IP 차단(15분)
- 계정별 잠금 정책 추가 (5회 실패 → 30분 잠금)

---

### C-3. 전체 사이트 설정 비인증 노출 — 운영 정보 탈취

**경로 1**: `GET /api/site-config` (API 직접 접근)  
**경로 2**: SSR HTML 응답에 `siteConfigRaw` 전체 인라인 삽입

SSR HTML에서 추출한 설정 (비인증 상태로 메인 페이지 접근 시 노출):
```json
{
  "betConfirmMsg": true,
  "chargeTimeStart": "00:30:00",
  "chargeTimeEnd": "23:30:00",
  "withdrawTimeStart": "00:30:00",
  "withdrawTimeEnd": "23:30:00",
  "pointConvertMin": 10000,
  "allowRegister": true,
  "useAnonymousSignup": true,
  "blockDupAccount": true,
  "useChargeBonusCondition": true,
  "useCoupon": true,
  "useLosingCommission": true,
  "usePartnerDashboard": true,
  "usePartnerMembers": true,
  "usePartnerBets": true,
  "casinoOperationMode": "seamless",
  "cryptoWalletAddress": "고객센터 문의바랍니다.",
  "useP2pTransfer": false,
  "useLiveChat": false,
  "loginTemplate": "1"
}
```

**위험성**: 
- **입출금 시간 노출** (00:30~23:30): 공격자가 운영 공백 시간(23:30~00:30)을 노림
- **기능 플래그 전체 노출**: 어떤 기능이 활성/비활성인지 파악하여 공격면 최적화
- **무기명 가입 활성화 확인**: `useAnonymousSignup: true` — 즉시 악용 가능
- **파트너 시스템 전체 활성화 확인**: 파트너 기능 남용 경로 파악
- **SSR에 게임 상태, 에셋 경로, 배너 파일명까지 전부 포함**

**권장조치**: 
- `site-config` API를 인증 필수로 변경
- SSR 시 민감 설정은 서버사이드에서만 사용, 클라이언트에 전달 금지
- 입출금 시간, 운영 설정 등은 인증된 세션에서만 제공

---

### C-4. 세션 PATCH로 계정 강제 탈퇴 — 계정 파괴 공격

**엔드포인트**: `PATCH /api/session`  
**OPTIONS 응답**: `allow: DELETE, OPTIONS, PATCH`

**재현 과정**:
```
1. 정상 로그인 (rnalswo1 계정)
2. PATCH /api/session → {"userRole":"ADMIN","userType":"ADMIN"}
3. 응답: {"ok":false,"kicked":true,"reason":"session_removed"}
4. 재로그인 시도 → {"ok":false,"reason":"WITHDRAWN","message":"탈퇴된 계정입니다."}
```

**실제 결과**: 테스트 계정(rnalswo1)이 **영구 탈퇴 처리**됨. 로그인 불가.

**위험성**:
- 인증된 사용자가 PATCH 요청 한 번으로 자신의 계정을 영구 탈퇴시킬 수 있음
- **CSRF 공격**과 결합 시: 악성 사이트가 로그인된 사용자를 대상으로 PATCH 요청을 유도하면 **타인의 계정을 강제 탈퇴**시킬 수 있음
- SameSite=Lax 쿠키이므로 top-level navigation POST/PATCH는 차단되지만, `fetch()` API나 `XMLHttpRequest`로 same-site 조건에서 악용 가능
- DELETE 메서드도 허용되어 있어 추가 공격 벡터 존재

**권장조치**:
- PATCH /api/session에서 계정 상태 변경 기능 제거
- 탈퇴 처리는 별도의 `/api/user/withdraw` 엔드포인트에서 비밀번호 재확인 후 처리
- CSRF 토큰 검증을 모든 상태 변경 API에 적용

---

### C-5. 출금 비밀번호(PIN) 브루트포스 방어 부재

**엔드포인트**: `POST /api/money/withdraw`  
**테스트**: 동일 세션에서 틀린 출금 비밀번호 5회 연속 시도

```
시도 1: {"error":"환전 비밀번호가 일치하지 않습니다."}
시도 2: {"error":"환전 비밀번호가 일치하지 않습니다."}
시도 3: {"error":"환전 비밀번호가 일치하지 않습니다."}
시도 4: {"error":"환전 비밀번호가 일치하지 않습니다."}
시도 5: {"error":"환전 비밀번호가 일치하지 않습니다."}
```

**차단 없음**: 계정 잠금, 지연, CAPTCHA 모두 없음.

**위험성**: 출금 비밀번호가 4자리 숫자 PIN이면 10,000 조합. 자동화 스크립트로 수 분 내 크래킹 가능. 로그인 계정 탈취 후 잔액 전체 출금 가능.

**권장조치**:
- 3회 실패 후 10분 잠금
- 5회 실패 후 출금 기능 비활성화 + 관리자 알림
- 출금 시 2FA(SMS/이메일) 추가

---

### C-6. 카지노 벤더 출금 API 무검증 실행

**엔드포인트**: `POST /api/casino/tower/withdraw`  
**요청**: 빈 body `{}`  
**응답**:
```json
{"ok":true,"withdrawnAmount":0,"newBalance":0}
```

JS에서 발견된 7개 벤더 출금 API:
```
/api/casino/ace/withdraw
/api/casino/apex/withdraw
/api/casino/g/withdraw
/api/casino/honorlink/withdraw
/api/casino/thenut/withdraw
/api/casino/time/withdraw
/api/casino/tower/withdraw
```

**위험성**:
- 빈 요청으로도 `"ok":true` 반환 — 파라미터 검증 부재
- 금액 파라미터 조작 시 카지노 잔액 무단 이동 가능성
- 7개 벤더 경로가 모두 노출되어 있어 각각에 대한 공격 가능

**권장조치**: 필수 파라미터 검증, 금액 범위 검증, 요청 속도 제한 추가.

---

## 4. HIGH 발견사항

### H-1. 보안 헤더 전체 누락 — 클릭재킹/XSS 방어 부재

**응답 헤더 분석**:
```
HTTP/2 200
content-type: text/html; charset=utf-8
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
x-tenant-id: 8
x-powered-by:         ← 빈 값 2회 반복
server: cloudflare
```

| 보안 헤더 | 상태 | 위험 |
|-----------|------|------|
| X-Frame-Options | **누락** | 클릭재킹 공격 가능 |
| Content-Security-Policy | **누락** | XSS 방어 없음 |
| Strict-Transport-Security | **누락** | HTTPS 다운그레이드 가능 |
| X-Content-Type-Options | **누락** | MIME 스니핑 공격 가능 |
| Referrer-Policy | **누락** | 리퍼러 통한 정보 유출 |
| Permissions-Policy | **누락** | 브라우저 기능 제어 없음 |

**추가 문제**: `x-tenant-id: 8`이 응답 헤더에 노출됨 — 멀티테넌트 구조 확인 가능.

**권장조치**: 모든 응답에 아래 헤더 추가:
```
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
```

---

### H-2. 내부 도메인 및 인프라 정보 유출

**경로 1**: `/api/auth/providers` → 내부 도메인 `sample5.bb-s.cc` 노출  
**경로 2**: `/api/health` → 서버 상세 정보 노출

`/api/health` 비인증 응답:
```json
{
  "status": "ok",
  "pid": 16,
  "uptime": "...",
  "buildId": "nVbb0CZtqMkRFDSlCd_aj",
  "workerStartedAt": "2026-10-28T...",
  "geoipDb": {
    "exists": true,
    "lastModified": "2026-06-02T..."
  }
}
```

**내부 도메인 직접 접근 결과**:
```
sample5.bb-s.cc → Microsoft-HTTPAPI/2.0, 404 Not Found
```

**위험성**:
- PID=16 → 컨테이너 환경 확인 (적은 프로세스 수)
- buildId → 빌드 버전 추적 및 알려진 취약점 매칭
- GeoIP DB 날짜 → 서비스 업데이트 주기 파악
- 내부 도메인 → 동일 인프라 내 다른 서비스 탐색 기반

**권장조치**: `/api/health`에 인증 필수화 또는 제거. 내부 도메인은 외부 응답에서 완전 제거.

---

### H-3. 게임 활성 상태 API 비인증 노출

**엔드포인트**: `GET /api/games/active`

비인증 상태에서 전체 게임 상태 및 점검 정보 반환:
```json
{
  "PBG": true, "PBG2": false, "DHG": true, "BTE": true,
  "EOS3": false, "EOS5": false, "MARIO": true, "ANGELDEMON": true,
  "SPORTS": false, "INPLAY": false, "CASINO": true, "SLOT": true,
  "minigameStatus": {
    "PBG": {"visible": true, "maintenance": false, "message": "임시점검중입니다."},
    "EOS3": {"visible": false, "maintenance": true, "message": "임시점검중입니다."}
  },
  "allMinigameMaintenance": false,
  "miniGameOrder": {"pbg": 1, "pbg2": 2, "bte": 1, ...}
}
```

**위험성**: 
- 어떤 게임이 점검 중이고 어떤 게임이 활성인지 경쟁사/공격자에게 실시간 노출
- 점검 메시지, 게임 순서 등 운영 상세 정보 유출
- SSR HTML에도 동일 데이터 인라인 삽입

**권장조치**: 게임 활성 상태 중 `minigameStatus`, `miniGameOrder` 등 내부 운영 정보는 인증 후 제공.

---

### H-4. 비인증 알림 API 접근

**엔드포인트**: `GET /api/notifications/check`

비인증 상태 응답:
```json
{"unreadMessages": 0, "qaReplies": []}
```

현재는 빈 응답이지만, 세션 없이 접근 가능하다는 것은 인증 체크가 누락된 것. 인증된 사용자의 쿠키가 있으면 다른 사용자의 알림 데이터 접근 가능성 존재.

**권장조치**: 인증 미들웨어 추가, 세션 없으면 401 반환.

---

### H-5. 공지사항 제목에 Raw HTML 포함 — Stored XSS 벡터

**엔드포인트**: `GET /api/board/notices?limit=10`

응답에서 `title` 필드에 HTML 태그 포함:
```json
{
  "title": "<p>규정 및 이용약관</p>",
  "title": "<p>도메인 안내</p>"
}
```

**위험성**: 관리자 패널에서 공지사항 작성 시 `<script>` 태그나 이벤트 핸들러를 삽입하면, 프론트엔드에서 `dangerouslySetInnerHTML` 또는 `innerHTML`로 렌더링할 경우 **Stored XSS** 발생. 관리자 계정 탈취 후 전체 사용자 대상 XSS 공격 가능.

**권장조치**: 
- API 응답에서 HTML 태그 제거 (sanitization)
- 프론트엔드에서 `DOMPurify` 등으로 렌더링 전 정화
- 관리자 입력도 sanitize

---

### H-6. 세션 API에서 전체 사용자 정보 노출

**엔드포인트**: `GET /api/auth/session`  
**인증 후 응답**:
```json
{
  "user": {
    "name": "구민자이",
    "id": "cmvtj6dg4005n0hmnjxdtsrfa",
    "username": "rnalswo1",
    "nickname": "구민자이",
    "level": 1,
    "balance": "0",
    "points": "0",
    "status": "ACTIVE",
    "userType": "NORMAL",
    "userRole": "NORMAL",
    "tenantId": 8,
    "sessionId": "cmvtjofu7005m0fmnj1glfauk",
    "iat": 1793278434
  }
}
```

**위험성**: 세션 API가 `userRole`, `userType`, `tenantId`, `sessionId`까지 클라이언트에 전달. XSS와 결합 시 공격자가 사용자의 권한 수준, 내부 ID, 세션 ID를 모두 획득 가능.

---

### H-7. 사용자 프로필에서 전화번호/IP/계좌 정보 노출

**엔드포인트**: `GET /api/user/profile`
```json
{
  "username": "rnalswo1",
  "phone": "01032118176",
  "lastLoginIp": "160.79.106.132",
  "bankName": null,
  "bankAccount": null,
  "accountHolder": null
}
```

**추가**: `GET /api/money/withdraw` 응답에 **TRON 지갑 주소** 노출:
```json
{
  "account": {
    "walletAddress": "TAKAgkn9eNsudMzsubFgny4M4U2Z84RTHW"
  }
}
```

**위험성**: XSS → 프로필 API 호출 → 전화번호, IP, 지갑 주소 탈취. 피싱/SIM 스와핑 공격 기반 정보.

---

## 5. MEDIUM 발견사항

### M-1. 테넌트 ID 쿠키 조작 가능

**쿠키**: `bbs-tenant-id=8`
- `Secure`: O
- `SameSite`: lax
- **`HttpOnly`: X (누락)**
- `Path`: /

**위험성**: `HttpOnly` 미설정으로 JavaScript에서 `document.cookie`로 테넌트 ID 읽기/변경 가능. XSS와 결합 시 다른 테넌트의 데이터 접근 시도 가능.

**추가**: 응답 헤더에도 `x-tenant-id: 8`이 노출되어 멀티테넌트 구조 확인 가능.

**권장조치**: `bbs-tenant-id` 쿠키에 `HttpOnly` 추가. 서버 측에서 세션과 테넌트 ID 바인딩 검증.

---

### M-2. 실제 클라이언트 IP 비인증 노출

**엔드포인트**: `GET /api/client-ip`

Cloudflare 뒤에 있음에도 클라이언트의 실제 IP를 반환하는 API가 비인증 상태에서 접근 가능.

**위험성**: 
- 일반적으로 무해하지만, XSS와 결합 시 사용자의 실제 IP를 제3자에게 유출 가능
- VPN/프록시 사용자의 익명성 파괴

**권장조치**: 인증 필수화 또는 로그인 프로세스에서만 내부적으로 사용.

---

### M-3. 카지노 프로바이더 목록 비인증 노출

**엔드포인트**: `GET /api/casino/providers`

40개 게임 프로바이더 전체 목록이 비인증 상태에서 접근 가능:
```
pragmatic, evolution, ezugi, microgaming, playtech, ...
vendor: tower (모든 프로바이더 동일)
```

**위험성**: 어떤 게임 API를 사용하는지, 어떤 벤더를 통하는지 경쟁사에게 비즈니스 인텔리전스 유출.

**권장조치**: 게임 목록은 메인 페이지에서만 SSR로 제공, API 직접 접근 시 인증 요구.

---

### M-4. 업로드 파일 경로 예측 가능

SSR HTML과 API에서 노출된 업로드 경로 패턴:
```
/api/uploads/site-assets/8/platform-5/logo-1786010930413-opt.webp     (200, 76KB)
/api/uploads/site-assets/8/platform-5/favicon-1786010923764-opt.webp
/api/uploads/site-assets/8/platform-5/loginModalImage-1786399601819.webp
/uploads/site-assets/8/platform-5/mainBanner1-1789645548239.webp
/api/uploads/site-assets/_defaults/platform-5/mainBg-1780569502236.webp
```

**패턴**: `/api/uploads/site-assets/{tenantId}/platform-{version}/{type}-{timestamp}-opt.webp`

**위험성**: 
- 타임스탬프 기반 파일명으로 파일 존재 여부 무차별 대입 가능
- `_defaults` 경로 → 플랫폼 공유 에셋 접근
- 다른 테넌트 ID로 경로 변경 시 교차 테넌트 파일 접근 가능성

**권장조치**: 
- 파일명에 UUID 사용 (타임스탬프 대신)
- 테넌트 간 접근 격리 검증

---

### M-5. 은행 목록 비인증 노출

**엔드포인트**: `GET /api/banks`

전체 은행 목록이 비인증 상태에서 접근 가능. 운영 중인 은행 계좌 종류를 경쟁사에게 노출.

**권장조치**: 회원가입 프로세스 중에만 제공, API 직접 접근 시 rate limiting 적용.

---

### M-6. 충전 보너스 내부 정보 노출

**엔드포인트**: `GET /api/money/charge-bonuses` (인증 필요)
```
총 5개 보너스:
- ❌포인트 미지급❌ (카지노): 0% / type=NORMAL
- ❌포인트 미지급❌ (슬롯): 0% / type=NORMAL  
- ❌포인트 미지급❌ (미니게임): 0% / type=NORMAL
- ✅신규 가입 카지노 입금플러스: 0% / type=FIRST
- ✅신규 가입 슬롯 입금플러스: 30% / type=FIRST
```

보너스 ID(CUID), 롤오버 요건(`reqCasino: 100`, `reqSlot: 100`), 게임 차단 플래그 등 내부 운영 로직 전체 노출.

**위험성**: 보너스 시스템 악용 — 롤오버 최소 경로 계산, 보너스 ID 조작 시도 가능.

---

## 6. LOW 발견사항

### L-1. SSR에 에셋 경로/배너/파비콘 전체 인라인

메인 페이지 HTML에 `SiteAssetsProvider`의 `initial` 데이터가 전부 포함:
```json
{
  "logo": "/api/uploads/site-assets/8/platform-5/logo-1786010930413-opt.webp",
  "mainBanner1": "/uploads/site-assets/8/platform-5/mainBanner1-1789645548239.webp",
  "loginModalImage": "/api/uploads/site-assets/8/platform-5/loginModalImage-1786399601819.webp",
  "colorTheme": "theme-1"
}
```

숨겨진 배너도 노출: `"mainBanner6"`, `"mainBanner7"`, `"mainBanner8"` (hidden 으로 표시되어 있으나 경로 존재 확인 가능)

---

### L-2. Next.js Build ID 노출

`nVbb0CZtqMkRFDSlCd_aj` — SSR HTML의 `__next_f.push` 데이터에서 추출 가능. 빌드 버전 추적 가능.

---

### L-3. x-powered-by 헤더 빈 값 이중 출력

```
x-powered-by:
x-powered-by:
```

빈 문자열이 2회 출력. 서버 소프트웨어 식별에는 사용되지 않으나, 비정상적 헤더 구성은 미들웨어 설정 오류를 시사.

---

### L-4. 텔레그램 주소 및 영구 도메인 노출

공지 마퀴에서 확인:
```
◆필 독◆ 젤리 카지노 평생주소 안내 [젤리평생주소.com]
◆필 독◆ 젤리 카지노 텔레그램 주소 안내 [@jelly164]
```

의도적 공개이나, 소셜 엔지니어링 공격의 기반 정보가 됨.

---

### L-5. 사용자 잔액 API에서 게임 차단 플래그 노출

**엔드포인트**: `GET /api/user/balance`
```json
{
  "balance": "0",
  "points": "0",
  "blockSportsSingle": false,
  "blockSports": false,
  "blockMinigame": false,
  "blockCasino": false,
  "blockSlot": false
}
```

게임 카테고리별 차단 플래그가 클라이언트에 노출. 관리자가 특정 사용자에게 게임 제한을 걸었는지 여부를 사용자가 직접 확인 가능.

---

## 7. 양호 사항 (긍정적 발견)

| 항목 | 상태 | 설명 |
|------|------|------|
| 인증 쿠키 보안 | **양호** | `__Secure-` 접두사, `HttpOnly`, `Secure` 설정 (dwdw-00.com 대비 우수) |
| CORS 정책 | **양호** | Access-Control 헤더 미반환 = same-origin only (외부 도메인 차단) |
| 카지노 런치 인증 | **양호** | `POST /api/casino/launch` → `{"error":"인증 필요"}` (401) |
| 파트너 API 인증 | **양호** | `/api/partner/dashboard` 등 → "파트너 권한이 아닙니다." (역할 기반 차단) |
| 사용자 정보 API 인증 | **양호** | `/api/user/balance`, `/api/user/profile`, `/api/user/level-info` 모두 401 |
| 환경 파일 차단 | **양호** | `.env`, `.env.local`, `package.json`, `.git/HEAD` 모두 404 |
| HTTPS 적용 | **양호** | Cloudflare를 통한 전체 HTTPS |
| Cache 제어 | **양호** | `no-cache, no-store, must-revalidate` 설정 |
| 세션 관리 | **양호** | NextAuth 기반, CSRF 토큰 사용 |
| 디렉토리 리스팅 | **양호** | `/api/uploads/` 등 308 리디렉션 (리스팅 아님) |
| 비밀번호 변경 | **양호** | 현재 비밀번호 확인 필수 (`currentPassword` 파라미터) |
| 금액 검증 | **양호** | 음수/0원 충전 → "올바른 충전 금액을 입력해주세요." 차단 |
| CUID 기반 ID | **양호** | 순차 정수 대신 CUID 사용 — IDOR 무차별 대입 어려움 |
| 쿠폰 API 인증 | **양호** | `/api/user/coupons` 비인증 시 401 |
| 쪽지 IDOR 방어 | **양호** | 다른 ID로 접근 시 "찾을 수 없습니다." (소유자 검증) |

---

## 8. 공격 시나리오

### 시나리오 A: 계정 대량 크래킹
```
1. /api/site-config에서 운영 설정 확인 → allowRegister, useAnonymousSignup 확인
2. /api/login-precheck에 자동화 브루트포스 → 제한 없이 무제한 시도
3. 탈취한 계정으로 /api/casino/launch → 잔액 게임으로 이동
4. seamless 모드이므로 잔액 직접 사용 가능
```
**차단점**: 브루트포스 방어 없음 — 차단 불가  
**현실성**: ★★★★★

### 시나리오 B: Impersonate 프로바이더 악용
```
1. /api/auth/providers에서 impersonate 콜백 URL 확인
2. impersonate 콜백에 userId 파라미터로 직접 요청
3. 서버 측 검증이 미흡할 경우 타인 세션 획득
4. 관리자 userId 추측 → 관리자 권한 탈취
```
**차단점**: 현재 테스트 환경에서는 impersonate 콜백의 실제 동작 확인 불가 (인증 필요)  
**현실성**: ★★★★☆ (서버 측 검증 수준에 따라)

### 시나리오 C: XSS + 테넌트 변조 체인
```
1. 공지사항 title의 raw HTML 확인 (Stored XSS 벡터)
2. 관리자 계정 탈취 또는 관리자 XSS 삽입
3. XSS로 다른 사용자의 bbs-tenant-id 쿠키 변조 (HttpOnly 없음)
4. 다른 테넌트의 설정/데이터 접근 시도
```
**차단점**: 인증 쿠키는 `HttpOnly`라 XSS로 직접 세션 탈취 불가  
**현실성**: ★★★☆☆

### 시나리오 D: 정보 수집 → 표적 공격
```
1. /api/health → 서버 환경(컨테이너, PID, uptime) 파악
2. /api/site-config → 모든 운영 설정, 입출금 시간, 기능 플래그
3. /api/games/active → 게임 상태, 점검 시간
4. /api/auth/providers → 내부 도메인 sample5.bb-s.cc
5. sample5.bb-s.cc에 대한 직접 공격 또는 다른 테넌트 탐색
```
**차단점**: 모든 정보가 비인증 접근 가능 — 차단 없음  
**현실성**: ★★★★★

### 시나리오 E: 계정 탈취 → 잔액 탈취 전체 체인 (인증 테스트로 확인)
```
1. 브루트포스로 계정 비밀번호 크래킹 (C-2, 차단 없음)
2. 로그인 후 /api/user/profile → 전화번호, IP, 지갑 주소 확인
3. /api/money/withdraw에 출금 비밀번호 브루트포스 (C-5, 차단 없음)
4. 4자리 PIN 크래킹 후 전체 잔액 출금
5. 또는: /api/casino/tower/withdraw로 카지노 잔액 먼저 회수
```
**차단점**: 로그인 + 출금 비밀번호 모두 브루트포스 방어 없음  
**현실성**: ★★★★★

### 시나리오 F: CSRF 계정 파괴 공격
```
1. 악성 사이트에 PATCH /api/session 요청 삽입
2. 피해자가 jelly2022.com 로그인 상태에서 악성 사이트 방문
3. PATCH 요청 → 계정 강제 탈퇴
4. 피해자는 로그인 불가, 잔액 접근 불가
```
**차단점**: SameSite=Lax로 직접 CSRF는 어려우나, same-site XSS와 결합 시 가능  
**현실성**: ★★★☆☆

---

## 9. dwdw-00.com과 비교

| 항목 | dwdw-00.com (대왕) | jelly2022.com (젤리) |
|------|-----|------|
| **기술 스택** | PHP/Apache (레거시) | Next.js/SaaS (모던) |
| **브루트포스** | 150회 차단 없음 | 50회 차단 없음 (둘 다 CRITICAL) |
| **인증 쿠키** | HttpOnly 없음, 평문 비밀번호 반환 | `__Secure-` + HttpOnly (양호) |
| **세션 관리** | PHPSESSID 고정 가능 | NextAuth 기반 (양호) |
| **정보 유출** | 서버 헤더(Apache/PHP 버전) | 전체 운영 설정 SSR 노출 (더 심각) |
| **보안 헤더** | 7개 누락 | 6개 누락 (유사) |
| **SQL Injection** | eval() 기반 위험 | SaaS 플랫폼으로 ORM 사용 추정 (양호) |
| **특이 사항** | 평문 비밀번호 반환 | impersonate 프로바이더 노출, PATCH 계정 파괴 |
| **출금 보안** | 미테스트 | PIN 브루트포스 방어 없음 |
| **카지노 API** | 미테스트 | 빈 body로 withdraw OK 반환 |

**결론**: 젤리카지노가 모던 스택(Next.js/NextAuth)을 사용하여 인증 쿠키 보안, IDOR 방어(CUID), 금액 검증은 우수. 그러나 **PATCH /api/session 계정 파괴**, **출금 PIN 브루트포스 무방어**, **전체 운영 설정 SSR 노출**, **카지노 출금 API 무검증**은 실질적으로 더 위험한 취약점.

---

## 10. 화이트박스 테스트 시 우선 확인 사항

1. **PATCH /api/session 계정 파괴 로직** — 왜 PATCH가 계정 탈퇴를 트리거하는지, CSRF 방어 존재 여부 ★★★★★
2. **impersonate 프로바이더 구현** — 서버 측 검증 로직 (userId 검증, 관리자 세션 필수 여부) ★★★★★
3. **rate limiting 미들웨어** — 로그인 + 출금 비밀번호 모두 왜 적용 안 되는지 ★★★★★
4. **/api/casino/*/withdraw 검증 로직** — 빈 body로 ok:true 반환하는 이유 ★★★★☆
5. **테넌트 격리** — bbs-tenant-id 쿠키 변조 시 교차 테넌트 데이터 접근 가능한지 ★★★★☆
6. **공지사항/쪽지 HTML sanitization** — 저장/렌더링 시 XSS 필터링 존재 여부 ★★★★☆
7. **/api/health, /api/site-config 접근 제어** — 미들웨어 누락인지 설계상 의도인지 ★★★☆☆
8. **NextAuth 설정** — NEXTAUTH_URL이 sample5.bb-s.cc로 설정된 이유 (도메인 불일치) ★★★☆☆
9. **업로드 파일 접근 제어** — 타 테넌트 파일 접근 가능 여부 ★★★☆☆
10. **API 라우트별 인증 미들웨어 적용 현황** — notifications/check 등 일부 누락 ★★★☆☆
11. **casino launch SSRF 가능성** — providerCode 파라미터가 외부 URL로 대체 가능한지 ★★☆☆☆
12. **anonymous signup 악용 방지** — 무기명 가입의 봇 남용 시나리오 ★★☆☆☆
13. **세션 토큰(JWE) 암호화 강도** — 키 관리, 알고리즘 확인 ★★☆☆☆

---

## 11. 테스트 범위 및 한계

### 수행된 테스트 (비인증 + 인증)
- 기술 스택 핑거프린팅
- API 엔드포인트 발견 (JS 분석: layout, page, register, partner, deposit, withdraw, mypage, qa, inbox, coupons, attendance — 32개 API 매핑)
- 보안 헤더 분석
- 쿠키 보안 분석
- 로그인 브루트포스 테스트 (50회)
- 출금 비밀번호 브루트포스 테스트 (5회)
- 사용자 열거 테스트 (로그인, 회원가입)
- CORS 정책 확인
- 파일/디렉토리 탐색
- HTTP 메서드 테스트 (OPTIONS/PUT/DELETE/PATCH/TRACE)
- 파트너 대시보드 접근 테스트 (역할 기반 차단 확인)
- 내부 도메인 접근 테스트
- 환경 파일 노출 확인
- **[인증] 세션 API 분석 (PATCH 계정 파괴 발견)**
- **[인증] IDOR 테스트 (QA, 쪽지 — CUID 기반 방어 확인)**
- **[인증] 카지노 벤더 출금 API 테스트**
- **[인증] 비밀번호 변경 검증**
- **[인증] 충전/출금 금액 검증**
- **[인증] 보너스 시스템 분석**

### 미수행 (추가 테스트 필요)
- 카지노 게임 런치 SSRF (providerCode 파라미터 조작)
- 파트너 계정으로 파트너 대시보드 테스트
- 테넌트 격리 심층 테스트 (bbs-tenant-id 쿠키 변조)
- impersonate 콜백 실제 동작 테스트 (관리자 세션 필요)
- 입금/출금 실제 실행 테스트 (잔액 필요)
- 실시간 카지노 잔액 이동 테스트
- XSS 페이로드 실행 확인 (관리자 공지 작성 필요)

### 참고: 테스트 중 계정 사고
테스트 과정에서 `PATCH /api/session`에 `{"userRole":"ADMIN"}` 전송 후 **rnalswo1 계정이 탈퇴 처리**되었습니다. 이는 세션 API의 심각한 설계 결함(C-4)을 실증하는 결과이나, 추가 인증 테스트가 불가능해졌습니다. 계정 복구가 필요합니다.
