# tweetykr.com 블랙박스 보안 점검 리포트

- **대상(Target):** `https://tweetykr.com/` (트위티 — 트위터형 커뮤니티 플랫폼)
- **점검 유형:** 블랙박스(외부 관찰) — 소스코드 미열람 상태
- **권한(Authorization):** 사이트 소유자/운영자 본인이 점검을 요청·승인 (self-owned)
- **원칙:** 비파괴(non-destructive)·저볼륨 요청만 사용. DoS/대량요청/브루트포스/데이터변조 미수행
- **작성일:** 2026-10-04
- **다음 단계:** 소스코드 확보 후 화이트박스 코드 리뷰, Firebase Security Rules 직접 점검

> 이 리포트는 "외부에서 관찰 가능한 표면"에 대한 것입니다.
> 실제 익스플로잇 가능 여부는 소스 분석/화이트박스 단계에서 확정합니다.

---

## 0. 환경 관련 유의사항 (관측 한계)

- 대상은 **Firebase Hosting**(Fastly CDN) 위에서 운영. SPA(Single Page Application) 구조로, 존재하지 않는 경로도 모두 `index.html`을 200으로 반환(SPA 폴백)하므로 서버측 경로 부재를 HTTP 상태코드로 판별 불가.
- 본 점검 실행 환경은 송신 TLS를 프록시가 종단하므로, 실제 서버 인증서/암호군/TLS 버전은 **SSL Labs 등 외부 도구로 별도 확인 필요.**
- Firebase 서비스(Realtime Database, Firestore) 직접 접근 테스트는 환경 분류기에 의해 일부 차단됨. 해당 항목은 수동 확인 권장.
- 능동 탐침은 엔드포인트당 단발성으로 최소화. 데이터 변조·삭제·계정 생성 등은 수행하지 않았음.

---

## 1. 기술 스택 지문 (Fingerprint)

| 항목 | 관측값 | 근거 |
|---|---|---|
| 호스팅 | **Firebase Hosting** (Fastly CDN) | `x-served-by: cache-iad-*`, `vary: x-fh-requested-host`, `/__/firebase/init.json` 정상 응답 |
| 프론트엔드 | **React** SPA | `<div id="root">`, React 에러 URL 참조 |
| 빌드 도구 | **Vite** | 에셋 해싱 패턴 (`index-BQVeNeGk.js`) |
| CSS | **Tailwind CSS v4.2.3** | CSS 파일 주석 |
| 폰트 | **Pretendard Variable** | CSS base 레이어 |
| 백엔드 | **Firebase** (Firestore + Realtime DB + Auth + Storage + Cloud Functions) | JS 번들 분석 |
| 리전 | **asia-northeast3** (서울) | Cloud Functions URL |
| 실시간 | **WebSocket** | JS 번들 내 WebSocket 참조 17건 |
| 라우팅 | **React Router** | 의존성 확인 |
| 결제 | **Sellix.io** | `api.sellix.io/v1/payment/session/initialize` 참조 |
| 지리정보 | **ipapi.co** | `fetch('https://ipapi.co/json/')` 호출 |
| 외부 서비스 | **Cloudflare Workers** | `worker-billowing-dawn-b2b4.rlaclrk3.workers.dev` |
| 소셜 연동 | **X(Twitter) OAuth** | `getTwitterAuth_v11`, `twitterIdToUid` Cloud Functions |

---

## 2. 발견 사항 (Findings)

심각도는 CVSS 정성 기준(블랙박스 관측 기반 추정치)입니다.

### 🟥 F-01 (Critical, 확정) Firebase Storage 공개 열거 — 전체 사용자 파일 노출

Firebase Storage 버킷(`tweetalk2.appspot.com`)이 **인증 없이 전체 디렉토리·파일 목록 열거 가능**.

```
GET https://firebasestorage.googleapis.com/v0/b/tweetalk2.appspot.com/o?delimiter=/
```

**노출된 디렉토리:**

| 디렉토리 | 추정 내용 | 위험도 |
|---|---|---|
| `avatars/` | 사용자 프로필 사진 | 개인정보 |
| `chats/` | **채팅 첨부파일** | 사적 대화 내용 |
| `posts/` | 게시글 첨부 이미지 | 콘텐츠 |
| `usercontent/` | 사용자 업로드 콘텐츠 | 개인정보 |
| `anonymous_photo/` | 익명 게시 사진 | 익명성 파괴 가능 |
| `cvAvatars/` | 이력서/커버 이미지? | 개인정보 |
| `appcontent/` | 앱 콘텐츠 | 내부 자료 |
| `mp/` | 미상 | 미확인 |

- 파일명에 사용자 식별자가 포함될 경우, **특정 사용자의 모든 업로드 파일을 열거·다운로드** 가능.
- `chats/` 디렉토리는 **사적 대화 첨부파일**이 포함될 가능성 높음 → 개인정보보호법 위반 소지.
- **즉시 조치 필요:** Firebase Storage Rules에서 `list` 권한을 인증 사용자로 제한, 가능하면 본인 파일만 열거 가능하게.

**재현:**
```bash
curl -sS "https://firebasestorage.googleapis.com/v0/b/tweetalk2.appspot.com/o?delimiter=/&maxResults=50"
```

---

### ~~F-02 (오탐) 소스맵 노출~~

> **정정:** 최초 점검 시 `.js.map` 요청이 HTTP 200을 반환해 소스맵 노출로 판단했으나,
> 재검증 결과 응답 본문은 **SPA 폴백 `index.html`** (1,451 bytes)이며 실제 소스맵이 아님.
> Firebase Hosting이 존재하지 않는 모든 경로에 200 + index.html을 반환하는 설정 때문.
> **소스맵은 배포되어 있지 않음. 양호.**

---

### 🔴 F-03 (High, 확정) Cloud Functions 미인증 접근 — 사용자 정보 노출 표면

다음 Cloud Functions가 **인증(Firebase Auth 토큰) 없이 호출 가능**:

| 함수 | 미인증 GET 응답 | 위험 |
|---|---|---|
| `twitterIdToUid` | `400 {"status":"fail","data":"Screen name is required"}` | Twitter 스크린네임 → UID 변환. 사용자 열거 가능 |
| `anonymousReply_V3` | `500` (파라미터 부족) | 익명 답글 — 인증 없이 호출 시 남용 가능성 |
| `dangerReaction` | `204` (정상 처리?) | 이름상 "위험 반응" 신고? 빈 POST에 204 반환 — 인증 확인 필요 |
| `memberWithdrwal` | `500` | **회원 탈퇴** — 인증 없이 접근 가능하면 Critical |
| `userInternet` | `500` | 사용자 인터넷 정보? |
| `userInternetDouble_V2` | `500` | 중복 확인? |
| `getTwitterAuth_v11` | `500` | Twitter OAuth — 토큰/시크릿 처리 로직 |

**특히 우려되는 항목:**
1. **`twitterIdToUid`**: 스크린네임만으로 내부 UID를 조회할 수 있다면, 사용자 열거(user enumeration) 및 IDOR 공격의 진입점.
2. **`memberWithdrwal`**: 철자 오류(`withdrawal`→`withdrawl`)로 보아 초기 개발 코드. 인증 없이 회원 탈퇴가 가능하면 계정 삭제 공격 가능.
3. **`dangerReaction`**: 빈 POST에 204 반환은 비정상. CORS preflight가 아닌 실제 처리일 가능성.

**해결:** 모든 Cloud Functions에 `context.auth` 검증 추가. `callable` 함수 사용 권장.

---

### 🔴 F-04 (High, 잠재) `dangerouslySetInnerHTML` 13건 — XSS 표면

JS 번들에서 React의 `dangerouslySetInnerHTML` 사용이 **13회** 확인됨.

- React는 기본적으로 XSS를 방지하나, `dangerouslySetInnerHTML`은 **의도적으로 이스케이프를 우회**하는 API.
- 사용자 입력(게시글, 프로필, 채팅 등)이 이 경로를 통해 렌더링되면 **저장형 XSS(Stored XSS)** 가능.
- 소스코드 확보 후 정확한 사용처 확인 필요 → **화이트박스 최우선 점검 항목.**

**추가 XSS 싱크:**
- `innerHTML` 직접 사용: **5건**
- `window.open`: 12건 (URL 검증 필요)
- `postMessage`/`onmessage`: 12건 (origin 검증 필요)

---

### 🟠 F-05 (Medium) 보안 헤더 부재

HTTPS 200 응답에 다음 헤더가 **모두 없음**:

| 헤더 | 상태 | 위험 |
|---|---|---|
| `Content-Security-Policy` | ❌ 없음 | XSS 완화 계층 부재. F-04와 결합 시 위험 |
| `X-Content-Type-Options` | ❌ 없음 | MIME 스니핑 가능 |
| `X-Frame-Options` / CSP `frame-ancestors` | ❌ 없음 | **클릭재킹** 가능 |
| `Referrer-Policy` | ❌ 없음 | 외부 링크 클릭 시 URL 정보 유출 |
| `Permissions-Policy` | ❌ 없음 | 불필요 브라우저 기능 미차단 |
| `Strict-Transport-Security` | ✅ `max-age=31556926` | **양호** |

**양호한 점:** HSTS가 약 1년(`31556926`초)으로 설정됨. HTTP→HTTPS 301 리다이렉트 정상 동작.

**해결:** Firebase Hosting의 `firebase.json`에서 `headers` 설정:
```json
{
  "headers": [{
    "source": "**",
    "headers": [
      {"key": "X-Content-Type-Options", "value": "nosniff"},
      {"key": "X-Frame-Options", "value": "DENY"},
      {"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
      {"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()"},
      {"key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' https://apis.google.com; ..."}
    ]
  }]
}
```

---

### 🟠 F-06 (Medium) Cloud Functions CORS 미설정 / 임의 Origin 허용 가능

Cloud Functions에 OPTIONS 요청 시 **500 에러** 반환:
```
OPTIONS /anonymousReply_V3 → 500
```

- CORS preflight가 정상 처리되지 않으면, **임의 Origin에서의 크로스사이트 호출이 허용되거나 차단이 일관적이지 않을 수 있음.**
- Cloud Functions에서 `cors` 미들웨어를 `origin: true`(모든 Origin 허용)로 사용하고 있을 가능성.
- 결제(Sellix)·회원탈퇴·사용자 정보 관련 함수에서 CORS가 느슨하면 **CSRF 유사 공격** 가능.

**화이트박스 확인:** 각 함수의 `cors` 설정과 `origin` 허용 목록.

---

### 🟠 F-07 (Medium) 정적 에셋 캐시 정책 부적절

| 리소스 | Cache-Control | 권장 |
|---|---|---|
| `index.html` | `max-age=3600` | `no-cache` 또는 `max-age=0, must-revalidate` |
| `index-BQVeNeGk.js` (해시 포함) | `max-age=3600` | `max-age=31536000, immutable` |
| `index-eDgMnnz5.css` (해시 포함) | `max-age=3600` | `max-age=31536000, immutable` |

- **해시가 포함된 에셋**: 내용이 바뀌면 파일명도 바뀌므로 1년 캐시 가능. 현재 1시간은 CDN 효율 저하.
- **index.html**: SPA 진입점으로 항상 최신이어야 함. 1시간 캐시는 배포 후 사용자가 구버전을 볼 수 있음.

**해결:** `firebase.json`의 `headers`에서 에셋별 캐시 정책 분리.

---

### 🟠 F-08 (Medium, 개인정보) 사용자 IP 지리정보 수집 — 제3자 전송

페이지 로드 시 **ipapi.co**로 사용자 IP를 전송하여 지리정보를 수집:

```javascript
fetch('https://ipapi.co/json/').catch(() => null)
```

- 게시글(`posts`) 컬렉션 조회와 동시에 호출 — 피드 로드 시 무조건 실행.
- 사용자 동의 없이 IP·위치 정보를 **제3자 서비스에 전송**하는 것은 개인정보보호법/GDPR 위반 소지.
- ipapi.co의 개인정보 처리방침에 의존하게 됨.

**해결:** 위치 기반 기능이 필요하면 서버측(Cloud Functions)에서 처리하거나, 사용자 동의 후 수집.

---

### 🟡 F-09 (Low/Info) Firebase 프로젝트 정보 완전 노출

`/__/firebase/init.json` 경로에서 Firebase 설정이 **인증 없이 전체 노출**:

```json
{
  "apiKey": "AIzaSyCk9M4k79dBfqMrb-nLAHD4zv_SK7jFHYs",
  "authDomain": "tweetalk2.firebaseapp.com",
  "databaseURL": "https://tweetalk2-default-rtdb.asia-southeast1.firebasedatabase.app",
  "messagingSenderId": "451743582754",
  "projectId": "tweetalk2",
  "storageBucket": "tweetalk2.appspot.com"
}
```

- Firebase API 키 자체는 **공개 식별자**이므로 단독으로는 위험하지 않음.
- 그러나 **프로젝트 ID/DB URL/Storage 버킷** 노출은 F-01(Storage 공개 열거) 등 다른 공격을 가능하게 하는 정보.
- `/__/firebase/init.json`은 Firebase Hosting 기본 경로로, 차단이 어려움.

**완화:** API 키 제한(HTTP Referer, 허용 API 제한)을 Google Cloud Console에서 설정.

---

### 🟡 F-10 (Low/Info) `robots.txt` — 전면 허용

```
User-agent: *
Disallow:
```

- 모든 크롤러에 모든 경로 허용. SPA라 크롤러가 실제 콘텐츠를 수집하긴 어렵지만, 의도적인 것인지 확인.
- `sitemap.xml`은 SPA 폴백(index.html)을 반환 → **실제 사이트맵 미제공**. SEO 관점 불리.

---

### 🟡 F-11 (Low/Info) OG 메타태그 오류

```html
<meta name="description" content="트위티는 트위터와 유사한 커뮤니티형 인섹트를 띠는 소통창구 입니다." />
```

- "**인섹트**"는 오타 (→ "인터페이스" 또는 다른 단어 의도?).
- `theme-color` 불일치: HTML `<meta>` = `#EFEFEF`, `manifest.json` = `#000000`.

---

### 🟡 F-12 (Info) Firebase Auth — 익명 가입 비활성

```
POST /accounts:signUp → {"error":{"message":"ADMIN_ONLY_OPERATION"}}
```

- 익명 회원가입 API 직접 호출은 차단됨. **양호.**
- 그러나 `createAuthUri`는 응답하므로, 이메일 기반 사용자 열거 가능 여부 추가 확인 필요.

---

### 🟡 F-13 (Info) 우클릭 차단

```html
<body oncontextmenu="return false">
```

- 보안 효과 없음 (DevTools에서 우회 가능). 사용자 경험만 저하.
- 콘텐츠 보호가 목적이라면 워터마크 등 다른 방법 권장.

---

## 3. 공격 표면 인벤토리 (화이트박스 분석 대상)

### Cloud Functions (asia-northeast3)

| 함수 | 성격 | 우선 점검 항목 |
|---|---|---|
| `twitterIdToUid` | Twitter → UID 변환 | **미인증 사용자 열거**, 레이트리밋, 입력검증 |
| `anonymousReply_V3` | 익명 답글 | 인증확인, 스팸 방지, 입력검증(XSS/인젝션) |
| `dangerReaction` | 신고/반응? | 인증확인, 빈 요청에 204 반환 원인, 남용 방지 |
| `memberWithdrwal` | **회원 탈퇴** | **인증·인가 필수 확인**, CSRF, 레이트리밋 |
| `getTwitterAuth_v11` | Twitter OAuth | 토큰/시크릿 처리, state 파라미터, 콜백 URL 검증 |
| `userInternet` / `userInternetDouble_V2` | 사용자 인터넷 정보 | 인증확인, 데이터 노출 범위, SSRF 가능성 |

### 클라이언트 보안 싱크

| 패턴 | 건수 | 점검 항목 |
|---|---|---|
| `dangerouslySetInnerHTML` | 13 | 사용자 입력이 렌더링되는지, 살균(sanitize) 여부 |
| `innerHTML` | 5 | DOM 기반 XSS |
| `window.open` | 12 | URL 검증, 오픈 리다이렉트 |
| `postMessage` | 12 | origin 검증 여부 |
| `localStorage` | 31 | 민감정보(토큰 등) 저장 여부 |
| `sessionStorage` | 10 | 동일 |
| `document.cookie` | 3 | 쿠키 직접 조작 목적 |

### 외부 서비스 연동

| 서비스 | URL | 점검 항목 |
|---|---|---|
| Sellix (결제) | `api.sellix.io/v1/payment/session/initialize` | 클라이언트에서 직접 호출 시 API 키 노출, 금액 변조 |
| ipapi.co (지리정보) | `ipapi.co/json/` | 개인정보 제3자 전송 동의 |
| Cloudflare Worker | `worker-billowing-dawn-b2b4.rlaclrk3.workers.dev` | 용도·인증·입력검증 |
| X/Twitter | `x.com/intent/user`, OAuth | OAuth 플로우 안전성 |

---

## 4. 화이트박스 단계 점검 계획

소스코드 확보 후 다음을 점검합니다.

1. **소스코드 리뷰**: 컴포넌트 구조, 라우팅, 인증 로직 전체 확인
2. **Firestore Security Rules**: `firestore.rules` 직접 확인 (Firebase Console 또는 CLI)
3. **Realtime Database Rules**: `.read`/`.write` 규칙이 `true`인 경로 확인
4. **Storage Rules**: `list`/`read`/`write` 권한 범위 (F-01의 근본 원인)
5. **Cloud Functions 인증**: 각 함수의 `context.auth` 검증 여부
6. **XSS 싱크**: `dangerouslySetInnerHTML`에 전달되는 데이터의 출처·살균
7. **결제 플로우**: Sellix API 호출 시 금액·상품 정보의 서버측 검증
8. **OAuth 플로우**: Twitter Auth의 state/nonce/콜백 URL 검증
9. **IDOR**: Firestore 문서 접근 시 소유자 검증 (타인 게시글/DM 접근)
10. **레이트리밋**: Cloud Functions·Firestore 쿼리의 남용 방지

---

## 5. 즉시 적용 가능한 완화책 (코드 변경 최소)

### 🚨 긴급 (금일 조치 권장)

1. **Firebase Storage Rules 수정** — 공개 열거 차단:
   ```
   rules_version = '2';
   service firebase.storage {
     match /b/{bucket}/o {
       match /{allPaths=**} {
         allow read: if request.auth != null;
         allow write: if request.auth != null
                      && request.auth.uid == resource.metadata.owner;
         allow list: if request.auth != null;
       }
     }
   }
   ```

### ⚠️ 단기 (1주일 이내)

2. **보안 헤더 추가** — `firebase.json`:
   ```json
   {
     "hosting": {
       "headers": [
         {
           "source": "**",
           "headers": [
             {"key": "X-Content-Type-Options", "value": "nosniff"},
             {"key": "X-Frame-Options", "value": "DENY"},
             {"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
             {"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()"}
           ]
         },
         {
           "source": "**/*.@(js|css|map|woff2|png|jpg|svg)",
           "headers": [
             {"key": "Cache-Control", "value": "max-age=31536000, immutable"}
           ]
         }
       ]
     }
   }
   ```

4. **Cloud Functions 인증 추가** — 최소한 `memberWithdrwal`과 `twitterIdToUid`:
   ```typescript
   // callable 함수로 전환 또는 토큰 검증 추가
   if (!context.auth) {
     throw new functions.https.HttpsError('unauthenticated', 'Authentication required');
   }
   ```

5. **Firebase API 키 제한** — Google Cloud Console → API & Services → Credentials:
   - HTTP Referer 제한: `tweetykr.com/*`만 허용
   - 사용 API 제한: 필요한 Firebase API만 활성화

### 📋 중기 (1개월 이내)

6. **ipapi.co 호출 제거** 또는 서버측 이전 + 사용자 동의
7. **CSP 헤더 도입** (Report-Only부터 시작)
8. **Cloud Functions CORS** origin 허용목록 설정 (`tweetykr.com`만)
9. **Firestore/RTDB Security Rules 전체 감사**
10. **OG 메타태그 수정** ("인섹트" 오타)

---

## 6. 부록 — 재현용 관측 명령 (비파괴)

```bash
# 응답 헤더 확인
curl -sS -D - -o /dev/null https://tweetykr.com/

# Firebase 설정 노출
curl -sS https://tweetykr.com/__/firebase/init.json

# Storage 공개 열거 (F-01)
curl -sS "https://firebasestorage.googleapis.com/v0/b/tweetalk2.appspot.com/o?delimiter=/&maxResults=10"

# Cloud Functions 미인증 접근 (F-03)
curl -sS https://asia-northeast3-tweetalk2.cloudfunctions.net/twitterIdToUid

# HTTP → HTTPS 리다이렉트 + HSTS
curl -sS -D - -o /dev/null http://tweetykr.com/
```

---

## 7. 심각도 요약

| # | 심각도 | 항목 | 상태 |
|---|---|---|---|
| F-01 | 🟥 Critical | Storage 공개 열거 | **확정** |
| F-02 | ~~Critical~~ | ~~소스맵 노출~~ | **오탐 — SPA 폴백** |
| F-03 | 🔴 High | Cloud Functions 미인증 | **확정** (일부 함수) |
| F-04 | 🔴 High | dangerouslySetInnerHTML 13건 | 잠재 (화이트박스 확정) |
| F-05 | 🟠 Medium | 보안 헤더 부재 | **확정** |
| F-06 | 🟠 Medium | CORS 미설정 | 잠재 |
| F-07 | 🟠 Medium | 캐시 정책 부적절 | **확정** |
| F-08 | 🟠 Medium | IP 지리정보 제3자 전송 | **확정** |
| F-09 | 🟡 Low | Firebase 프로젝트 정보 노출 | 정보성 |
| F-10 | 🟡 Low | robots.txt 전면 허용 | 정보성 |
| F-11 | 🟡 Low | OG 메타태그 오류 | 정보성 |
| F-12 | 🟡 Low | Auth 익명 가입 차단 | **양호** |
| F-13 | 🟡 Info | 우클릭 차단 | 무해하나 불필요 |

---

*본 리포트는 소유자 승인 하에 수행된 블랙박스 점검 결과입니다.*
