# 젤리 카지노 (jelly2022.com) 블랙박스 보안 테스트 리포트

**대상**: https://jelly2022.com/  
**테스트 일시**: 2026-10-29  
**테스트 방식**: 비인증(Unauthenticated) 블랙박스 테스트  
**테스터**: 자동화 보안 스캐너 + 수동 분석  
**버전**: v1

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
| **CRITICAL** | 3 |
| **HIGH** | 5 |
| **MEDIUM** | 5 |
| **LOW** | 4 |
| **합계** | **17** |

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

## 7. 양호 사항 (긍정적 발견)

| 항목 | 상태 | 설명 |
|------|------|------|
| 인증 쿠키 보안 | **양호** | `__Secure-` 접두사, `HttpOnly`, `Secure` 설정 (dwdw-00.com 대비 우수) |
| CORS 정책 | **양호** | Access-Control 헤더 미반환 = same-origin only (외부 도메인 차단) |
| 카지노 런치 인증 | **양호** | `POST /api/casino/launch` → `{"error":"인증 필요"}` (401) |
| 파트너 API 인증 | **양호** | `/api/partner/dashboard`, `/partner/losing-available` 등 모두 401 |
| 사용자 정보 API 인증 | **양호** | `/api/user/balance`, `/api/user/profile`, `/api/user/level-info` 모두 401 |
| 환경 파일 차단 | **양호** | `.env`, `.env.local`, `package.json`, `.git/HEAD` 모두 404 |
| HTTPS 적용 | **양호** | Cloudflare를 통한 전체 HTTPS |
| Cache 제어 | **양호** | `no-cache, no-store, must-revalidate` 설정 |
| 세션 관리 | **양호** | NextAuth 기반, CSRF 토큰 사용 |
| 디렉토리 리스팅 | **양호** | `/api/uploads/` 등 308 리디렉션 (리스팅 아님) |

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
| **특이 사항** | 평문 비밀번호 반환 | impersonate 프로바이더 노출 |

**결론**: 젤리카지노가 모던 스택을 사용하여 기본적인 인증/세션 보안은 우수하지만, **정보 유출**(site-config, health, games/active 등)과 **브루트포스 방어 부재**는 대왕카지노와 동등하거나 더 심각.

---

## 10. 화이트박스 테스트 시 우선 확인 사항

1. **impersonate 프로바이더 구현** — 서버 측 검증 로직 확인 (userId 검증, 관리자 세션 필수 여부)
2. **rate limiting 미들웨어** — 왜 적용되지 않는지, 코드 존재 여부
3. **테넌트 격리** — bbs-tenant-id 쿠키 변조 시 다른 테넌트 데이터 접근 가능한지
4. **공지사항 HTML sanitization** — 저장 시 XSS 필터링 존재 여부
5. **/api/health, /api/site-config 접근 제어** — 미들웨어 누락인지 설계상 의도인지
6. **NextAuth 설정** — NEXTAUTH_URL이 sample5.bb-s.cc로 설정된 이유 (도메인 불일치)
7. **업로드 파일 접근 제어** — 타 테넌트 파일 접근 가능 여부
8. **API 라우트별 인증 미들웨어 적용 현황** — 일부 엔드포인트만 401 반환
9. **casino launch SSRF 가능성** — provider 파라미터가 외부 URL로 대체 가능한지
10. **anonymous signup 악용 방지** — 무기명 가입의 악용 시나리오

---

## 11. 테스트 범위 및 한계

### 수행된 테스트
- 기술 스택 핑거프린팅
- API 엔드포인트 발견 (JS 분석: layout.js, page.js, register.js, partner JS)
- 보안 헤더 분석
- 쿠키 보안 분석
- 브루트포스 테스트 (50회)
- 사용자 열거 테스트 (로그인, 회원가입)
- CORS 정책 확인
- 파일/디렉토리 탐색
- HTTP 메서드 테스트
- 파트너 대시보드 접근 테스트
- 내부 도메인 접근 테스트
- 환경 파일 노출 확인

### 미수행 (인증 필요)
- 인증 후 IDOR 테스트 (사용자 ID, 거래 ID)
- 입금/출금 API 조작
- 카지노 게임 런치 SSRF
- 파트너 대시보드 기능 테스트
- 쪽지/QA 게시판 쓰기 테스트
- 세션 하이재킹/고정 테스트
- 테넌트 격리 심층 테스트
- impersonate 콜백 실제 동작 테스트

**인증된 테스트 계정이 있으면 훨씬 더 깊은 테스트가 가능합니다.**
