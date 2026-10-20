# cb-1111.com 블랙박스 보안 점검 리포트

- **대상(Target):** `https://cb-1111.com/`
- **점검 유형:** 블랙박스(외부 관찰) — 소스코드 미열람 상태
- **권한(Authorization):** 사이트 소유자/운영자 본인이 점검을 요청·승인 (self-owned)
- **원칙:** 비파괴(non-destructive)·저볼륨 요청만 사용. DoS/대량요청/브루트포스/챌린지 우회 미수행
- **작성일:** 2026-10-20
- **다음 단계:** 화이트박스(소스코드) 확보 후 앱 계층 점검

> **핵심 결론:** cb-1111.com은 **Cloudflare 매니지드 챌린지(Managed Challenge)** 를 전 경로에 적용하고,
> 엣지에서 **강력한 보안 헤더 세트**를 설정하고 있어, 비브라우저 기반 블랙박스 앱 계층 점검이
> **엣지에서 전면 차단**됩니다. 앞서 점검한 dw-04.com·swt-222.com과 달리, 외부에서 관찰 가능한
> 공격 표면이 매우 좁습니다. 앱 계층 취약점 점검은 **화이트박스(소스) 단계** 또는 소유자 제공
> 인증 세션 기반 점검이 필요합니다.

---

## 0. 환경 관련 유의사항 (관측 한계)

- 대상은 **Cloudflare 뒤에서 사이트 전역 매니지드 챌린지**(`cf-mitigated: challenge`, `cType: managed`)를 강제합니다. 루트(`/`)를 포함해 `/robots.txt`, `/sitemap.xml`, `/js/*`, `/css/*`, 앱 추정 경로(`/common/*`, `/login`, `/index.php`, `/index.jsp` 등) **모두 `403` 챌린지 인터스티셜**(“Just a moment…”)로 반환됩니다.
- 따라서 **curl/비브라우저 클라이언트로는 실제 애플리케이션 콘텐츠(HTML/JS/엔드포인트)에 도달 불가**. HTML 지문, AJAX 엔드포인트, 로그인/회원가입 흐름, 쿠키 플래그 등 앱 계층 관측이 **원천적으로 불가능**합니다.
- 유일한 예외: `/favicon.ico` → `404`(챌린지 없이 엣지 응답). 정적 파비콘만 엣지에서 직접 처리됨.
- 본 점검 실행 환경은 **송신 TLS를 프록시가 종단**하므로 실제 서버 인증서/암호군/TLS 버전은 판별 불가. → 외부 도구(SSL Labs)로 별도 확인.
- 챌린지 우회(headless 브라우저 자동 solve, 토큰 재사용 등)는 **수행하지 않았습니다**(비파괴 원칙 + 탐지회피 미수행). 자동화된 챌린지 우회는 그 자체로 WAF 탐지회피에 해당하여 점검 범위에서 제외.

---

## 1. 기술 스택 지문 (Fingerprint) — 엣지 관측 한정

| 항목 | 관측값 | 근거 |
|---|---|---|
| CDN/WAF | **Cloudflare** | `server: cloudflare`, `cf-ray`, `cf-mitigated: challenge`, `report-to`/`nel` |
| 봇 방어 | **Managed Challenge (Turnstile/JS)** | `cType: 'managed'`, `/cdn-cgi/challenge-platform/...`, `challenges.cloudflare.com` |
| 백엔드 | **미상(엣지 차단)** | 챌린지 통과 전 원본 헤더 노출 없음 → 서버 종류/언어 식별 불가 |
| 챌린지 플랫폼 | `cvId: '3'`, `cTplV:5` | Cloudflare challenge opt 블록 |

> dw-04.com(PHP)·swt-222.com(Java/IIS)와 달리 **백엔드 지문이 노출되지 않음** — 엣지가 원본을 가림. 긍정적.

---

## 2. 발견 사항 (Findings)

블랙박스 가시성이 엣지로 한정되므로, 아래는 **엣지(Cloudflare) 계층 관측**에 대한 것입니다.

### 🟢 F-01 (긍정적, 확정) 사이트 전역 매니지드 챌린지로 자동화 공격 표면 차단

- 전 경로에 Cloudflare 매니지드 챌린지 적용 → **스크래핑/스캐닝/브루트포스/크리덴셜 스터핑/자동화 익스플로잇**이 앱에 도달하기 전 엣지에서 차단.
- `meta http-equiv="refresh" content="360"` + JS orchestrate 스크립트 기반 정식 Cloudflare 챌린지.
- swt-222.com(WAF 없음)·dw-04.com(시그니처 WAF, 앱 접근 가능)과 비교해 **봇/자동화 방어가 현저히 강함**.

### 🟢 F-02 (긍정적, 확정) 엣지에서 포괄적 보안 헤더 세트 설정

챌린지 응답(및 추정상 앱 응답)에 다음 보안 헤더가 **모두 present**:

| 헤더 | 값 | 효과 |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'`; nonce 기반 script-src 등 | XSS/인젝션 완화 (챌린지 페이지 기준 매우 엄격) |
| `X-Frame-Options` | `SAMEORIGIN` | 클릭재킹 차단 |
| `X-Content-Type-Options` | `nosniff` | MIME 스니핑 차단 |
| `Referrer-Policy` | `same-origin` | 리퍼러 누출 최소화 |
| `Permissions-Policy` | camera/mic/geolocation 등 대부분 `()` 비활성 | 민감 기능 차단 |
| `Cross-Origin-Opener-Policy` | `same-origin` | 크로스오리진 창 격리 |
| `Cross-Origin-Embedder-Policy` | `require-corp` | 크로스오리진 리소스 격리 |
| `Cross-Origin-Resource-Policy` | `same-origin` | 리소스 반출 제한 |
| `Origin-Agent-Cluster` | `?1` | 오리진 단위 격리 |

- 이는 **swt-222.com의 F-05(보안 헤더 전면 부재)와 정반대**의 양호한 상태. 단, 이 헤더가 **엣지(Cloudflare)에서 주입된 것인지 원본 앱 설정인지**는 챌린지 통과 전이라 단정 불가 → 화이트박스에서 확인.

### 🟡 F-03 (Info) 앱 계층 보안 헤더 일관성 — 화이트박스 확인 필요

- 위 보안 헤더는 **Cloudflare 챌린지 페이지**의 것. 챌린지 통과 후 **실제 앱 응답에도 동일 헤더가 유지되는지**(특히 CSP가 앱 페이지에서도 엄격한지, nonce가 아닌 `unsafe-inline`으로 느슨해지지 않는지)는 블랙박스로 확인 불가.
- 카지노 앱 특성상 인라인 스크립트/이벤트 핸들러가 많으면 CSP가 앱 단에서 크게 완화됐을 가능성 → 화이트박스에서 **앱 응답의 실제 CSP** 확인 필수.

### 🟡 F-04 (Info) 쿠키 플래그·세션 관리 — 관측 불가

- 챌린지 통과 전이라 앱의 `Set-Cookie`(세션 쿠키 이름, `HttpOnly`/`Secure`/`SameSite` 플래그)를 관측할 수 없음.
- 관측된 쿠키는 Cloudflare 챌린지 관련 쿠키(`cf_chl_*`)뿐.

### ⚪ F-05 (관측 불가) 앱 계층 취약점 일체

- 로그인/회원가입 흐름, AJAX 엔드포인트, 입력 검증, XSS/SQLi/CSRF/IDOR/SSRF/금전 로직 등 **앱 계층 전부 블랙박스 관측 불가**.
- 이전 두 사이트에서 확정했던 유형(postMessage XSS, 쿠키 DOM XSS, 서버오류 DOM 삽입, RSA 키 노출 등)이 cb-1111.com에도 존재하는지는 **코드 없이는 판단 불가**.

---

## 3. 이전 점검 대상과의 비교

| 항목 | dw-04.com | swt-222.com | cb-1111.com |
|---|---|---|---|
| CDN/WAF | Cloudflare (시그니처) | **없음** | **Cloudflare 매니지드 챌린지** |
| 앱 접근(비브라우저) | 가능 | 가능 | **불가(전역 챌린지)** |
| 백엔드 지문 노출 | PHP 노출 | Java/IIS 노출 | **미노출(엣지 차단)** |
| 보안 헤더 | 대부분 부재 | **전면 부재** | **포괄적 present** |
| 클릭재킹 방어 | 앱엔 없음 | 없음 | **X-Frame-Options 있음** |
| 블랙박스 가시성 | 높음 | 높음 | **매우 낮음(엣지 한정)** |

> cb-1111.com은 **엣지 방어 태세가 세 사이트 중 가장 강함**. 블랙박스로 드러나는 표면이 거의 없다는 것은 긍정적이나, **원본(origin) 앱의 실제 취약점은 가려져 있을 뿐 제거된 것이 아님** — 챌린지를 통과한 정상 사용자/세션 컨텍스트에서는 앞선 사이트와 동일한 클라이언트측·금전 로직 취약점이 존재할 수 있음.

---

## 4. 블랙박스 한계와 권장 점검 경로

cb-1111.com은 엣지 챌린지로 인해 **외부 비인증 블랙박스로는 유의미한 앱 점검이 불가**합니다. 다음 중 하나가 필요합니다:

1. **화이트박스(소스코드)** — 가장 효과적. 이전 두 사이트와 동일 코드베이스/프레임워크를 공유하는지부터 확인(동일 운영사라면 swt-222의 F-01/F-02/F-16/F-06 유형이 그대로 존재할 개연성 높음).
2. **소유자 제공 인증 세션 + 챌린지 통과 환경**에서의 그레이박스 점검 — 소유자가 Cloudflare 챌린지를 우회할 수 있는 테스트 경로(IP 허용목록, 테스트 우회 규칙)를 제공하면 앱 계층 점검 가능.
3. **오리진 직접 점검** — Cloudflare 뒤 원본 서버 IP에 소유자 승인하에 직접 접근(오리진이 Cloudflare만 신뢰하도록 설정됐는지도 함께 확인: 오리진 직노출 시 챌린지 전체가 무력화됨 → **오리진 IP 보호 상태 확인 권장**).

### 엣지 설정 관련 확인 포인트 (소유자/운영자용)

- **오리진 IP 숨김 확인:** Cloudflare를 우회해 오리진 IP로 직접 접근 가능하면 챌린지/보안헤더가 전부 무력화됨. 오리진 방화벽이 Cloudflare IP 대역만 허용하는지 확인.
- **앱 응답 CSP 유지 확인:** 챌린지 페이지뿐 아니라 실제 앱 페이지에서도 CSP가 엄격한지(특히 `script-src`에 `unsafe-inline`/와일드카드가 없는지).
- **챌린지 예외 경로 점검:** API/웹훅/결제 콜백 등 챌린지 예외로 둔 경로가 있으면 그곳이 실제 공격 표면 → 해당 경로만 별도 블랙박스/화이트박스 점검.

---

## 5. 부록 — 재현용 관측 명령(비파괴)

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# 전역 매니지드 챌린지 확인 (cf-mitigated: challenge, 403, "Just a moment...")
curl -sS -D - -o /dev/null -A "$UA" https://cb-1111.com/

# 앱 추정 경로도 모두 챌린지로 차단되는지 확인
for p in / /robots.txt /js/script.js /common/loginChk /index.php /login; do
  curl -sS -o /dev/null -w "%{http_code}  $p\n" -A "$UA" "https://cb-1111.com$p"
done   # → 전부 403 (favicon.ico만 404)

# 보안 헤더 세트 확인 (CSP/XFO/COOP/COEP/CORP/Permissions-Policy)
curl -sS -D - -o /dev/null -A "$UA" https://cb-1111.com/ | \
  grep -iE 'content-security-policy|x-frame-options|x-content-type|referrer-policy|permissions-policy|cross-origin'
```

---

*본 리포트는 소유자 승인 하에 수행된 블랙박스 점검 결과입니다. cb-1111.com은 엣지(Cloudflare 매니지드 챌린지) 방어로 인해 비브라우저 블랙박스 앱 계층 점검이 불가하며, 실질적 취약점 점검은 화이트박스(소스코드) 또는 소유자 제공 그레이박스 환경에서 수행해야 합니다.*
