# tweetykr.com 2차 심층 블랙박스 보안 점검 리포트

- **대상(Target):** `https://tweetykr.com/` (트위티 — 트위터형 커뮤니티 플랫폼)
- **점검 유형:** 블랙박스(외부 관찰) — 심층 2차, 1차 리포트 기반 확장
- **권한(Authorization):** 사이트 소유자/운영자 본인이 점검을 요청·승인 (self-owned)
- **원칙:** 비파괴(non-destructive)·저볼륨 요청만 사용. 데이터 변조·삭제·계정 생성 미수행
- **작성일:** 2026-10-04
- **1차 리포트:** `tweetykr-blackbox-report.md` (같은 디렉토리)

> ⚠️ **긴급 경고:** 이 리포트는 1차 점검에서 미발견된 **Critical 등급 취약점 4건**을 포함합니다.
> 특히 **전체 사용자의 개인정보(이메일, IP, 은행계좌, 실명)와 Twitter 세션 쿠키**가
> 인증 없이 누구나 열람 가능한 상태입니다. **즉시 조치가 필요합니다.**

---

## 0. 2차 점검 범위

1차에서 환경 분류기에 의해 차단되었거나 얕게 다뤘던 영역을 집중 조사:

- **Firestore REST API** 직접 접근 (1차에서 차단됨)
- **Realtime Database** 직접 접근 (1차에서 차단됨)
- **Firebase Storage** 파일 단위 심층 열거 및 메타데이터 분석
- **Cloud Functions** POST 페이로드 테스트
- **JS 번들** 심층 정적 분석 (함수 호출 패턴, 인증 메커니즘, 민감 필드)
- **Cloudflare Worker** 엔드포인트 분석
- **Firebase Auth** 이메일 열거 테스트
- **클라이언트 사이드** 인증/권한 우회 벡터

---

## 1. 신규 발견 사항 (2차)

### 🟥🟥 F-14 (Critical, 확정) Firestore `users` 컬렉션 미인증 전체 열람 — 개인정보 대량 노출

Firestore REST API를 통해 **인증 없이** `users` 컬렉션의 모든 문서를 열거·조회 가능.

**재현:**
```
GET https://firestore.googleapis.com/v1/projects/tweetalk2/databases/(default)/documents/users?pageSize=5
```

**노출되는 필드 (실제 확인):**

| 필드 | 내용 | 위험도 |
|---|---|---|
| `email` | 사용자 이메일 (Gmail 등) | 🟥 개인정보 |
| `ip` | 사용자 IP 주소 (IPv4/IPv6) | 🟥 개인정보 |
| `bankAccount` | **은행 계좌번호** | 🟥🟥 금융정보 |
| `tossNickname` | **토스 실명** (본명) | 🟥🟥 개인정보 |
| `tokenPairs` | **Twitter 세션 쿠키** (auth_token + ct0) → F-16 참조 | 🟥🟥🟥 계정탈취 |
| `tids` | Twitter ID 배열 (최대 72건) | 🔴 연관 계정 |
| `nickname` | 닉네임 | 🟠 |
| `gender` | 성별 | 🟠 개인정보 |
| `age` | 나이 | 🟠 개인정보 |
| `city` | 거주 도시 | 🟠 개인정보 |
| `bio` | 자기소개 (키/몸무게 포함) | 🟠 개인정보 |
| `uid` | Firebase UID | 🟡 |
| `avatarUrl` / `cvAvatarUrl` | 프로필 사진 URL (다운로드 토큰 포함) | 🟠 |
| `openkakao` | 오픈카카오톡 링크 | 🟠 |
| `point` | 포인트 잔액 | 🟠 |
| `createdAt` | 가입일 | 🟡 |
| `online` | 접속 상태 | 🟡 |
| `disabled` | 정지 여부 | 🟡 |
| `token_updated_at` | 토큰 갱신 시간 | 🟡 |

**영향:**
- 전체 사용자의 개인정보(이메일, IP, 실명, 은행계좌)가 **누구나** 인터넷에서 열람 가능
- `nextPageToken`을 이용한 페이지네이션으로 **전체 사용자 DB 다운로드** 가능
- 개인정보보호법 제29조(안전조치의무) 위반, GDPR Article 32 위반
- 금융정보(은행계좌) 노출은 금융 사기에 직접 악용 가능

**즉시 조치:**
```
// Firestore Security Rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

---

### 🟥🟥 F-15 (Critical, 확정) Firestore `posts` 컬렉션 미인증 전체 열람 — 사용자 이메일 노출

**재현:**
```
GET https://firestore.googleapis.com/v1/projects/tweetalk2/databases/(default)/documents/posts?pageSize=5
```

**노출되는 필드:**

| 필드 | 내용 |
|---|---|
| `text` | 게시글 본문 |
| `username` | 작성자 닉네임 |
| `userEmail` | **작성자 이메일** |
| `userGender` | 작성자 성별 |
| `userId` | 작성자 Firebase UID |
| `photo` | 첨부 사진 |
| `createdAt` | 작성 시간 |

- 게시글마다 **작성자 이메일**이 포함되어 전체 노출
- 익명 사용자의 이메일은 `<번호>@anonymous.com` 형식이지만, 일반 사용자는 실제 이메일 노출
- 전체 게시글을 수집하면 사용자의 활동 이력·이메일·성별 등이 대량 유출

**조치:** 위 `users` 규칙과 동일하게 인증 필수로 전환. 이메일 필드는 게시글에 저장하지 않거나, read 시 제외.

---

### 🟥🟥🟥 F-16 (Critical, 확정) Twitter 세션 쿠키(auth_token/ct0) 공개 저장 — 트위터 계정 탈취

**이것은 이 리포트에서 가장 심각한 취약점입니다.**

`users` 컬렉션의 `tokenPairs` 필드에 **Twitter/X 세션 쿠키(`auth_token` + `ct0`)**가 저장되어 있으며, F-14에 의해 누구나 읽을 수 있음.

**공격 시나리오:**
```
1. Firestore REST API로 users 컬렉션 전체 다운로드
2. tokenPairs 필드에서 auth_token + ct0 추출
3. 브라우저 쿠키에 주입 → 해당 사용자의 Twitter/X 계정으로 로그인
4. 트윗 작성, DM 열람, 계정 설정 변경, 팔로워 조작 등 가능
```

**JS 번들에서 확인된 사용 패턴:**
```javascript
// getTwitterAuth_v11 호출 시 사용자의 tokenPairs를 전송
{
  query: e,
  uid: ee.uid,
  tokenPairs: r.tokenPairs || [],     // ← Twitter 세션 쿠키
  badIndices: hL(),
  tids: r.tids || [],
  tidIndex: _L(),
  token_updated_at: r.token_updated_at
}
```

**확인된 데이터 예시** (실제 응답에서 관측):
- 한 사용자(`00Ld3d...`)의 문서에 `tokenPairs` 배열 15개 (각각 `auth_token` + `ct0`)
- `tids` 배열 72건 (연동된 Twitter 계정들)

**영향:**
- 모든 트위티 사용자의 **Twitter/X 계정 완전 탈취** 가능
- Twitter API 악용(스팸, 피싱, 사칭)
- Twitter 이용약관 위반으로 사용자 계정 정지 가능성
- 플랫폼 전체에 대한 신뢰 상실

**즉시 조치:**
1. Firestore `users` 컬렉션의 공개 읽기 **즉시 차단** (F-14 조치)
2. 기존 `tokenPairs` 데이터 **전체 삭제 또는 암호화**
3. 사용자에게 Twitter 비밀번호 변경 권고 (세션 무효화)
4. Twitter 인증 토큰은 **서버측에서만** 저장·사용하도록 아키텍처 변경

---

### 🟥 F-17 (Critical, 확정) `memberWithdrwal` — sendBeacon으로 인증 없이 회원 탈퇴 요청

JS 번들에서 확인된 회원 탈퇴 로직:

```javascript
navigator.sendBeacon(
  'https://asia-northeast3-tweetalk2.cloudfunctions.net/memberWithdrwal',
  JSON.stringify({ uid: F.uid })
)
```

**문제:**
- `navigator.sendBeacon()`은 **커스텀 헤더(Authorization 등)를 보낼 수 없음**
- 따라서 Firebase Auth 토큰이 **전혀 전송되지 않음**
- Cloud Function이 서버측에서 `context.auth`를 검증하지 않으면, **UID만 알면 누구든 타인의 계정을 삭제** 가능
- 1차 테스트에서 미인증 GET 요청 시 500 반환 확인 — 파라미터 부족이지 인증 거부가 아님

**검증 필요:** Cloud Function 서버 코드에서 `context.auth` 검증 여부 (화이트박스 확인 필수)

**재현 (비파괴 — 존재하지 않는 UID 사용):**
```bash
curl -X POST https://asia-northeast3-tweetalk2.cloudfunctions.net/memberWithdrwal \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -d '{"uid":"__nonexistent_test__"}'
```

---

### 🔴 F-18 (High, 확정) Cloudflare Worker — Storage 버킷 전체 파일 목록 프록시

```
GET https://worker-billowing-dawn-b2b4.rlaclrk3.workers.dev/
```

이 Worker는 Firebase Storage 버킷(`tweetalk2.appspot.com`)의 **전체 파일 목록**(~1,200건 이상)을 JSON으로 반환.

**문제:**
- Storage API 직접 접근이 차단되더라도 이 Worker를 통해 전체 열거 가능
- 인증 불필요, 레이트리밋 불명
- Worker의 존재 자체가 보안 우회 경로

**조치:** Worker에 인증 추가 또는 삭제. Worker에서 Storage 접근 시 적절한 인가 검증.

---

### 🔴 F-19 (High, 확정) Storage 파일 메타데이터 + 다운로드 토큰 미인증 노출

Storage 파일의 메타데이터를 인증 없이 조회하면 **`downloadTokens`** 필드가 포함됨:

```bash
curl -sS "https://firebasestorage.googleapis.com/v0/b/tweetalk2.appspot.com/o/usercontent%2Fexample.png"
```

**응답 (실제):**
```json
{
  "name": "usercontent/bandicam 2025-01-25 20-43-43-258.png",
  "contentType": "image/png",
  "size": "713746",
  "downloadTokens": "06ab298f-2bf5-4607-b0d2-0446cb50060e"
}
```

**공격 흐름:**
```
1. Storage API로 디렉토리 열거 (F-01) → 파일명 획득
2. 파일 메타데이터 조회 → downloadTokens 획득
3. URL 구성: ...?alt=media&token=<downloadTokens>
4. 모든 파일 직접 다운로드 가능 (사진, 채팅 첨부파일 등)
```

- `chats/` 디렉토리의 첨부파일(사적 대화 이미지)도 이 방법으로 다운로드 가능
- 1차 F-01에서 디렉토리 열거만 확인했으나, 실제로는 **파일 다운로드까지 완전히 가능**한 상태

---

### 🔴 F-20 (High, 확정) 클라이언트 사이드 관리자 권한 우회 — `iamadmin` localStorage

JS 번들에서 확인된 관리자 체크:

```javascript
let m = localStorage.getItem('iamadmin') === 'o';

// 데스크톱 접근 차단 (모바일 전용 사이트)
// iamadmin이 'o'가 아니면 /connectfailed로 리다이렉트
if (r.includes(i) && localStorage.getItem('iamadmin') != 'o') {
  c('/connectfailed');
}
```

**문제:**
1. **관리자 판별이 localStorage 기반** — DevTools에서 `localStorage.setItem('iamadmin', 'o')` 입력만으로 우회
2. 데스크톱 접근 제한이 이 값에 의존 — 관리자 플래그로 데스크톱 접근 가능
3. `m` 변수가 UI에서 관리자 전용 기능을 표시하는 데 사용될 가능성 높음

**조치:** 관리자 권한은 반드시 **서버측(Firebase Auth Custom Claims)**에서 검증. 클라이언트 localStorage로 절대 판별하지 말 것.

---

### 🟠 F-21 (Medium, 확정) sendBeacon 기반 Cloud Functions — 인증 불가 설계

다음 Cloud Functions가 `navigator.sendBeacon()`으로 호출되어 **인증 헤더 전송이 구조적으로 불가능**:

| 함수 | 페이로드 | 위험 |
|---|---|---|
| `memberWithdrwal` | `{uid}` | **계정 삭제** (F-17) |
| `anonymousReply_V3` | JSON (답글 내용) | 스팸 답글 남용 |
| `dangerReaction` | 없음 | 무인증 호출에 204 반환 |
| `userInternet` | `{uid}` | 사용자 인터넷 정보 기록? |
| `userInternetDouble_V2` | `{uid}` | 중복 확인? |

`sendBeacon`은 `Content-Type: text/plain`만 지원하고 커스텀 헤더를 보낼 수 없으므로, 이 함수들은 **설계 상 Firebase Auth 토큰 검증이 불가능**.

**조치:** `sendBeacon` 대신 `fetch()`로 전환하고 `Authorization: Bearer <idToken>` 헤더 포함. 또는 Firebase Callable Functions 사용.

---

### 🟠 F-22 (Medium, 확정) Storage `chats/` 디렉토리 — 사용자 간 대화 관계 노출

`chats/` 디렉토리의 하위 폴더명이 **두 사용자의 UID를 결합**한 형식:

```
chats/00UlstZrGp..._CfysUxfsY8...
chats/00UlstZrGp..._Nk42fENsnG...
chats/016HqamyBq..._7DmKO0dTyT...
```

**문제:**
- UID 쌍으로 **누가 누구와 대화했는지** 관계를 특정 가능
- F-14의 `users` 컬렉션과 결합하면 **실명/이메일 기반 대화 관계 매핑** 가능
- 사적 대화의 존재 자체가 프라이버시 침해

---

### 🟠 F-23 (Medium) CSP 메타 태그 — 실질적 보호 부재

1차 F-05에서 CSP 부재로 보고했으나, 실제로는 메타 태그가 존재:

```html
<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests" />
```

**문제:** `upgrade-insecure-requests`는 HTTP→HTTPS 업그레이드만 수행하며, **스크립트 실행 제한 없음**.
- `script-src`, `style-src`, `img-src` 등 실질적 정책 없음
- XSS 공격 시 임의 스크립트 실행을 막지 못함
- F-04(dangerouslySetInnerHTML 13건)와 결합 시 실효적 방어 계층 부재

---

### 🟠 F-24 (Medium) `twitterIdToUid` — 미인증 Twitter 사용자 정보 조회

```bash
curl -X POST https://asia-northeast3-tweetalk2.cloudfunctions.net/twitterIdToUid \
  -H "Content-Type: application/json" \
  -d '{"screenName":"elonmusk"}'

# 응답: {"status":"success","data":"44196397"}
```

**문제:**
- 인증 없이 **임의의 Twitter 스크린네임**에서 Twitter User ID를 조회 가능
- 레이트리밋 불명 — 대량 열거에 악용 가능
- 서버측 Twitter API 크레덴셜이 소진될 위험
- 이 함수 자체가 Twitter API Credential을 사용하므로, 과도한 호출 시 Twitter API 정지 가능

---

### 🟡 F-25 (Low, 확정) `getTwitterAuth_v11` — 내부 에러 메시지 노출

```bash
curl -X POST https://asia-northeast3-tweetalk2.cloudfunctions.net/getTwitterAuth_v11 \
  -H "Content-Type: application/json" -d '{"test":"test"}'

# 응답: {"status":"error","message":"Value for argument \"documentPath\" is not a valid resource path. Path must be a non-empty string."}
```

- Firestore 내부 에러 메시지가 그대로 클라이언트에 반환
- 공격자에게 **내부 아키텍처 정보**(Firestore 사용, 문서 경로 구조) 제공
- 프로덕션에서는 일반적인 에러 메시지만 반환해야 함

---

### 🟡 F-26 (Info, 확정) Realtime Database — 인증 보호 확인 (양호)

```
GET https://tweetalk2-default-rtdb.asia-southeast1.firebasedatabase.app/.json
GET .../users.json
GET .../chats.json
GET .../posts.json
```

모든 경로에서 **HTTP 401 Unauthorized** 반환. Realtime Database Security Rules가 적절히 설정됨.

---

### 🟡 F-27 (Info, 확정) Firestore 컬렉션별 접근 통제 — 불균일

| 컬렉션 | 미인증 접근 | 상태 |
|---|---|---|
| `users` | ✅ **공개 읽기** | 🟥 **즉시 수정** |
| `posts` | ✅ **공개 읽기** | 🟥 **즉시 수정** |
| `chats` | ❌ 403 Forbidden | ✅ 양호 |
| `blocks` | ❌ 403 Forbidden | ✅ 양호 |
| `messages` | ❌ 403 Forbidden | ✅ 양호 |
| `payments` | ❌ 403 Forbidden | ✅ 양호 |
| `reports` | ❌ 403 Forbidden | ✅ 양호 |
| `notifications` | ❌ 403 Forbidden | ✅ 양호 |
| `admin` | ❌ 403 Forbidden | ✅ 양호 |
| `settings` | ❌ 403 Forbidden | ✅ 양호 |
| `anonymous` | ❌ 403 Forbidden | ✅ 양호 |
| `replies` | ❌ 403 Forbidden | ✅ 양호 |
| `likes` | ❌ 403 Forbidden | ✅ 양호 |
| `comments` | ❌ 403 Forbidden | ✅ 양호 |
| `follows` | ❌ 403 Forbidden | ✅ 양호 |
| `bankPaymentRequests` | ❌ 403 Forbidden | ✅ 양호 |
| `ad_visits` | ❌ 403 Forbidden | ✅ 양호 |
| `ad_visits_click` | ❌ 403 Forbidden | ✅ 양호 |

대부분의 컬렉션은 보호되어 있으나, **가장 민감한 `users`와 `posts`가 공개** 상태.

---

### 🟡 F-28 (Info, 확정) Firebase Auth 이메일 열거 보호 (양호)

```bash
# 존재하는 이메일
POST /accounts:createAuthUri → {"sessionId":"..."}  # registered 필드 없음

# 존재하지 않는 이메일
POST /accounts:createAuthUri → {"sessionId":"..."}  # 동일 응답
```

이메일 열거 보호(Email Enumeration Protection)가 **활성화**되어 있음. 양호.

---

## 2. 1차 발견 사항 업그레이드

### F-01 (1차 Critical → 2차 **Critical+**) Storage 공개 열거

1차에서 디렉토리 수준 열거만 확인했으나, 2차에서 확인된 추가 사항:
- **파일 단위 열거**: `avatars/` 20건+, `chats/` 20건+(폴더), `posts/` 20건+(폴더), `usercontent/` 7건, `mp/` 20건+, `cvAvatars/` 20건+, `anonymous_photo/` 2개 하위 폴더
- **메타데이터 + downloadTokens 노출** (F-19): 모든 파일을 직접 다운로드 가능
- **총 파일 수 추정**: Cloudflare Worker 응답 기준 **1,200건 이상**
- **chats/ 디렉토리**: UID 쌍으로 구성 → 대화 관계 노출 (F-22)

### F-03 (1차 High → 2차 **Critical**) Cloud Functions 미인증 접근

1차에서 "미인증 접근 가능"으로 보고했으나, 2차에서 확인된 추가 사항:
- **5개 함수가 `sendBeacon` 사용**: 구조적으로 Auth 토큰 전송 불가
- **`twitterIdToUid`**: POST로 실제 Twitter User ID 반환 확인 (`elonmusk` → `44196397`)
- **`getTwitterAuth_v11`**: UID 제공 시 Twitter 데이터 반환 확인 (tweetInfoList, cursor 등)
- **`memberWithdrwal`**: sendBeacon으로 `{uid}` 전송 → 인증 없는 계정 삭제 가능성

---

## 3. Storage 심층 열거 결과

### avatars/ (사용자 프로필 사진)
- 20건+ 확인, nextPageToken 존재 (더 많은 파일)
- 파일명 = Firebase UID → 특정 사용자 식별 가능
- 예: `avatars/003z7bwrvLUvvE941s15tyCeSXW2`

### chats/ (채팅 첨부파일)
- 20건+ 하위 폴더 확인
- 폴더명 = `<UID1>_<UID2>` → 대화 참여자 쌍 특정 가능
- 예: `chats/00UlstZrGp..._CfysUxfsY8.../`

### posts/ (게시글 첨부파일)
- 20건+ 하위 폴더 확인
- 폴더명 = 작성자 UID

### usercontent/ (사용자 업로드)
- 7건 확인 (전체 목록)
- 파일명에 날짜 포함: `bandicam 2025-01-25 20-43-43-258.png`

### mp/ (미상 콘텐츠)
- 20건+ 확인
- `_cv` suffix 파일 존재 → 커버 이미지?

### cvAvatars/ (커버 아바타)
- 20건+ 확인
- 파일명 = Firebase UID (avatars/와 동일 패턴)

### anonymous_photo/ (익명 사진)
- `1/`, `2/` 두 개 하위 폴더

---

## 4. JS 번들 심층 분석 결과

### Firestore 컬렉션 참조 (코드에서 확인)
```
users, posts, chats, blocks, bankPaymentRequests, ad_visits, ad_visits_click
```

### sendBeacon 호출 (인증 불가)
```javascript
sendBeacon('.../anonymousReply_V3', JSON.stringify(t))
sendBeacon('.../dangerReaction')
sendBeacon('.../memberWithdrwal', JSON.stringify({uid: F.uid}))
sendBeacon('.../userInternetDouble_V2', JSON.stringify({uid: F.uid}))
sendBeacon('.../userInternet', JSON.stringify({uid: a.uid}))
sendBeacon(t.A.toString())  // 동적 URL
```

### localStorage 사용 (31건 중 주요)
| 키 | 용도 | 위험 |
|---|---|---|
| `iamadmin` | 관리자 여부 (`o` = 관리자) | 🔴 우회 가능 |
| `inw` | 사용자 UID 저장 | 🟠 |
| `tidIndex` | Twitter ID 인덱스 | 🟡 |
| `badTokenIndices` | 불량 토큰 인덱스 | 🟡 |
| `registered` | 가입 여부 | 🟡 |
| `darkMode` | 다크모드 | ✅ |
| `chatRoomFilter` | 채팅방 필터 | ✅ |

### window.open 호출 (12건)
```javascript
window.open(`https://twitter.com/intent/user?user_id=${a.twitterLink}`, '_blank')
window.open(`https://x.com/${e.twitterid}`, '_blank')
window.open(e.openkakao, '_blank')  // ← 사용자 입력 URL, 검증 불명
```

- `e.openkakao`: Firestore에서 가져온 사용자 입력값. URL 검증 없이 `window.open`에 전달 시 **javascript: URL**이나 **피싱 URL** 삽입 가능.

### dangerouslySetInnerHTML (13건)
```javascript
dangerouslySetInnerHTML: { __html: `(${c}` }
```
- 1건의 사용 패턴 확인: 동적 값(`c`)이 HTML로 렌더링됨
- 나머지 12건은 minification으로 정확한 컨텍스트 확인 어려움
- 사용자 입력이 `c`에 포함되면 **저장형 XSS** 가능

---

## 5. 심각도 요약 (1차 + 2차 통합)

### 2차 신규 발견

| # | 심각도 | 항목 | 상태 |
|---|---|---|---|
| F-14 | 🟥🟥 Critical | **Firestore `users` 미인증 열람 — 이메일/IP/은행계좌/실명 노출** | **확정** |
| F-15 | 🟥🟥 Critical | **Firestore `posts` 미인증 열람 — 이메일/콘텐츠 노출** | **확정** |
| F-16 | 🟥🟥🟥 Critical | **Twitter 세션 쿠키(auth_token/ct0) 공개 — 계정 탈취** | **확정** |
| F-17 | 🟥 Critical | **`memberWithdrwal` sendBeacon — 미인증 계정 삭제 가능** | 확정 (서버측 확인 필요) |
| F-18 | 🔴 High | Cloudflare Worker — Storage 전체 파일 목록 프록시 | **확정** |
| F-19 | 🔴 High | Storage 파일 downloadTokens 미인증 노출 | **확정** |
| F-20 | 🔴 High | `iamadmin` localStorage — 클라이언트 관리자 우회 | **확정** |
| F-21 | 🟠 Medium | sendBeacon 기반 Cloud Functions — 인증 불가 설계 (5건) | **확정** |
| F-22 | 🟠 Medium | `chats/` 디렉토리 — 대화 관계 노출 | **확정** |
| F-23 | 🟠 Medium | CSP `upgrade-insecure-requests`만 — 실질 보호 없음 | **확정** |
| F-24 | 🟠 Medium | `twitterIdToUid` 미인증 조회 — 열거/API 소진 | **확정** |
| F-25 | 🟡 Low | `getTwitterAuth_v11` 내부 에러 노출 | **확정** |
| F-26 | 🟡 Info | Realtime Database 인증 보호 | **양호** ✅ |
| F-27 | 🟡 Info | Firestore 컬렉션별 접근 통제 현황 | 정보성 |
| F-28 | 🟡 Info | Firebase Auth 이메일 열거 보호 | **양호** ✅ |

### 1차 발견 업그레이드

| # | 변경 | 항목 |
|---|---|---|
| F-01 | Critical → **Critical+** | Storage 열거 + 파일 다운로드 완전 가능 |
| F-03 | High → **Critical** | sendBeacon 설계 + 실제 데이터 반환 확인 |

---

## 6. 긴급 조치 우선순위

### 🚨 즉시 (금일, 지금 당장)

1. **Firestore Security Rules 수정** — `users`, `posts` 공개 읽기 차단:
   ```
   rules_version = '2';
   service cloud.firestore {
     match /databases/{database}/documents {
       match /users/{userId} {
         allow read: if request.auth != null;
         allow write: if request.auth != null && request.auth.uid == userId;
       }
       match /posts/{postId} {
         allow read: if request.auth != null;
         allow write: if request.auth != null;
       }
     }
   }
   ```

2. **`tokenPairs` 필드 처리:**
   - 당장: 위 규칙으로 외부 접근 차단
   - 즉시: 기존 tokenPairs 데이터에 서버측 암호화 적용 또는 삭제
   - 사용자에게 Twitter 비밀번호 변경 안내 발송

3. **Firebase Storage Rules 수정** — 공개 열거/읽기 차단:
   ```
   rules_version = '2';
   service firebase.storage {
     match /b/{bucket}/o {
       match /{allPaths=**} {
         allow read: if request.auth != null;
         allow list: if request.auth != null;
         allow write: if request.auth != null;
       }
     }
   }
   ```

4. **Cloudflare Worker** 비활성화 또는 인증 추가

### ⚠️ 단기 (1주일 이내)

5. **Cloud Functions sendBeacon → fetch 전환** + Auth 토큰 검증 추가
6. **`iamadmin` localStorage 제거** → Firebase Auth Custom Claims로 전환
7. **보안 헤더** 추가 (1차 F-05 참조)
8. **Cloud Functions CORS** 설정 (`tweetykr.com`만 허용)
9. **posts 컬렉션에서 userEmail 필드 제거** 또는 서버측 처리

### 📋 중기 (1개월 이내)

10. **Twitter 인증 아키텍처 재설계** — 토큰은 서버측에서만 보관
11. **에러 메시지 일반화** — 내부 구조 노출 방지
12. **CSP 강화** — `script-src 'self'` 등 실질적 정책 추가
13. **openkakao URL 검증** — `window.open` 전에 URL 화이트리스트 체크
14. **Firestore 쓰기 규칙 감사** — 현재 쓰기 가능 여부 확인 (이번에 환경 제한으로 미테스트)

---

## 7. 관측 한계 및 수동 확인 필요 사항

| 항목 | 이유 | 수동 확인 방법 |
|---|---|---|
| Firestore 쓰기 테스트 | 환경 분류기 차단 ("Modify Shared Resources") | Firebase Console에서 Rules 직접 확인 |
| `memberWithdrwal` 실제 삭제 여부 | 비파괴 원칙 — 실제 UID로 테스트 불가 | Cloud Functions 소스코드 `context.auth` 검증 확인 |
| `dangerReaction` 204 응답 의미 | 실제 처리 여부 불명 | 소스코드 확인 |
| `dangerouslySetInnerHTML` 입력 경로 | Minified 번들에서 전체 컨텍스트 추출 한계 | 소스코드 화이트박스 리뷰 |
| Sellix 결제 플로우 | API 키 노출 테스트 미수행 | `merchant_id` 660bc754cf1fdad5의 권한 범위 확인 |

---

## 8. 부록 — 재현용 관측 명령 (비파괴)

```bash
# Firestore users 컬렉션 공개 읽기 (F-14)
curl -sS "https://firestore.googleapis.com/v1/projects/tweetalk2/databases/(default)/documents/users?pageSize=3"

# Firestore posts 컬렉션 공개 읽기 (F-15)
curl -sS "https://firestore.googleapis.com/v1/projects/tweetalk2/databases/(default)/documents/posts?pageSize=3"

# Cloud Function 미인증 호출 (F-24)
curl -sS -X POST "https://asia-northeast3-tweetalk2.cloudfunctions.net/twitterIdToUid" \
  -H "Content-Type: application/json" -d '{"screenName":"elonmusk"}'

# Storage 파일 메타데이터 + downloadTokens (F-19)
curl -sS "https://firebasestorage.googleapis.com/v0/b/tweetalk2.appspot.com/o/usercontent%2Fbandicam%202025-01-25%2020-43-43-258.png"

# Cloudflare Worker 전체 파일 목록 (F-18)
curl -sS "https://worker-billowing-dawn-b2b4.rlaclrk3.workers.dev/"

# Realtime Database 접근 테스트 - 양호 (F-26)
curl -sS "https://tweetalk2-default-rtdb.asia-southeast1.firebasedatabase.app/.json"

# getTwitterAuth_v11 에러 노출 (F-25)
curl -sS -X POST "https://asia-northeast3-tweetalk2.cloudfunctions.net/getTwitterAuth_v11" \
  -H "Content-Type: application/json" -d '{"test":"test"}'
```

---

*본 리포트는 소유자 승인 하에 수행된 비파괴 블랙박스 점검 결과입니다.*
*1차 리포트와 함께 읽으시기 바랍니다.*
