# suddanow.com (섯다나우) 부정행위·조작 분석 보고서

> **대상**: https://suddanow.com/  
> **분석일**: 2026-10-29  
> **방식**: 비인증 블랙박스 (JS 정적 분석 + HTTP/WS 엔드포인트 탐색)  
> **한계**: Socket.IO 직접 연결 미수행 (보안 분류기 차단). 인증 후 room:state 데이터 미확인.

---

## 1. 사이트 개요

| 항목 | 내용 |
|------|------|
| 서비스명 | 섯다나우 (SuddaNow) |
| 설명 | 실시간 온라인 섯다 (화투) 게임 |
| 스택 | Next.js (Turbopack) + Socket.IO + Caddy |
| 통신 | REST API 없음 — **모든 기능이 Socket.IO** (/ws) 경유 |
| 인증 | Socket.IO `auth:login` → JWT 토큰 → sessionStorage/localStorage |
| 화폐 | USDT (TRC20) 기반 충전/출금 |
| 관리 | `/admin` 라우트 (admin/superadmin 롤) |

---

## 2. 발견사항 요약

| # | 심각도 | 항목 | 상태 |
|---|--------|------|------|
| F-1 | **CRITICAL** | devUserId 백도어 — 프로덕션 코드에 개발자 인증 우회 경로 존재 | 확인 필요 |
| F-2 | **HIGH** | 토큰 localStorage 저장 — XSS 시 세션 탈취 가능 | 확인됨 |
| F-3 | **HIGH** | 관리자 페이지 JS 전체 노출 — 관리 API 구조 공개 | 확인됨 |
| F-4 | **MEDIUM** | 클라이언트 족보 평가 함수 — 게임 로직 역공학 용이 | 확인됨 |
| F-5 | **MEDIUM** | room:state 카드 노출 가능성 — 상대 패 데이터 사전 전송 여부 미확인 | 검증 필요 |
| F-6 | **LOW** | Socket.IO polling 핸드셰이크 무인증 접속 가능 | 확인됨 |

---

## 3. 상세 분석

### F-1 [CRITICAL] devUserId 백도어

**위치**: `getSocket()` 함수 (chunk `3rq9aa16926-b.js`)

```javascript
// 토큰 없으면 devUserId를 서버에 전송
auth: token ? { token: token } : {
  devUserId: new URLSearchParams(window.location.search).get("dev")
             ?? window.sessionStorage.getItem("sudda-now-dev-user-id")
}
```

**위험**: 프로덕션 서버가 `devUserId`를 수락할 경우:
- `suddanow.com/?dev=admin` → 관리자 계정 탈취
- `suddanow.com/?dev=<any-user-id>` → 임의 사용자 사칭
- 크레딧 조작, 게임 조작, 출금 탈취 가능

**확인 방법**: 서버 코드에서 `devUserId` 처리 로직 확인 필요. 프로덕션에서 반드시 비활성화 필수.

**부정행위 관련**: 이 백도어가 활성화되어 있으면, 제3자가 관리자 권한으로 접속하여 게임 결과 조작, 크레딧 조작이 가능.

---

### F-2 [HIGH] 토큰 저장 방식

```javascript
// 키: "sudda-now-token"
// 저장소: sessionStorage 또는 localStorage (로그인 유지 체크 시)
window.localStorage.setItem("sudda-now-token", token)
```

- **HttpOnly 쿠키 미사용** — XSS 공격으로 토큰 탈취 가능
- 채팅 기능(`chat:send`)이 있어 stored XSS 벡터 존재 가능

---

### F-3 [HIGH] 관리자 API 전체 노출

`/admin` 라우트의 JS 청크가 인증 없이 다운로드 가능하여, 관리 기능 전체 구조가 노출:

**발견된 관리자 Socket.IO 이벤트 (22개)**:

| 이벤트 | 기능 |
|--------|------|
| `admin:users` | 전체 사용자 목록 조회 |
| `admin:userDetail` | 사용자 상세 정보 |
| `admin:setRole` | 권한 변경 (admin/member) |
| `admin:adjustCredit` | 크레딧 지급/차감 |
| `admin:signups` | 가입 신청 목록 |
| `admin:resolveSignup` | 가입 승인/거절 |
| `admin:withdraws` | 출금 요청 목록 |
| `admin:resolveWithdraw` | 출금 승인/거절 |
| `admin:liveGames` | 진행 중 게임 실시간 조회 |
| `admin:rounds` | 게임 라운드 이력 |
| `admin:userRounds` | 특정 사용자 게임 이력 |
| `admin:money` | 재무 정보 |
| `admin:settings` | 사이트 설정 조회 |
| `admin:updateSettings` | 사이트 설정 변경 |
| `admin:updateUser` | 사용자 정보 수정 |
| `admin:partners` | 파트너 목록 |
| `admin:makePartner` | 파트너 지정 |
| `admin:updatePartner` | 파트너 정보 수정 |
| `admin:setPartnerCode` | 파트너 코드 설정 |
| `admin:changePartnerCode` | 파트너 코드 변경 |
| `admin:partnerSettlement` | 파트너 정산 |
| `admin:grantLottery` | 복권 지급 |

**부정행위 관련**: `admin:liveGames`와 `admin:rounds`를 통해 진행 중인 게임을 관찰하고, `admin:adjustCredit`으로 크레딧을 조작할 수 있는 구조. 서버 측 권한 검증이 핵심.

---

### F-4 [MEDIUM] 클라이언트 측 족보 평가 함수

`evaluatePair(card1, card2)` 함수가 클라이언트 JS에 완전히 노출:

```
카테고리: kwangttaeng(광땡) > ttaeng(땡) > special > kkeut(끗) > mangtong(망통)

광땡 파워: 3-8광땡=28, 1-8광땡=27, 그 외=26
땡 파워: 15 + month (1땡=16, 10땡=25)
끗 파워: 0 + (month1+month2)%10

특수패: 구사(gusa), 알리, 독사, 장사, 장삥, 세륙 등
카운터 시스템: 특정 패 조합에 대한 역전 메커니즘
```

- SUDDA_DECK: 20장 (1~10월 x 2벌, 각 광 여부 포함)
- 역공학으로 최적 전략 도출 가능 (일반 수학적 분석과 동일하므로 심각도 MEDIUM)

---

### F-5 [MEDIUM] room:state 카드 노출 가능성

게임 상태는 `room:state` 이벤트로 클라이언트에 전송:

```javascript
socket.on("room:state", (table) => setState({ table }))
```

**관찰 결과**:
- HwatuCard 컴포넌트는 `faceDown` prop으로 뒤집기 제어
- `card` prop이 null이면 뒷면 표시
- 서버가 상대 카드 데이터를 보내되 UI에서만 숨기는 경우 → **WebSocket 스니핑으로 상대 패 확인 가능**
- 서버가 공개 전까지 상대 카드 데이터를 아예 안 보내는 경우 → 안전

**검증 필요**: 인증 후 게임 방 참여 시 `room:state` 데이터를 캡처하여, 상대 카드 ID가 공개 전에 포함되는지 확인 필수.

**이것이 가장 핵심적인 부정행위/조작 가능성** — 서버가 카드를 미리 전송하면, 브라우저 DevTools > Network > WS 탭에서 상대 패를 실시간으로 볼 수 있음.

---

### F-6 [LOW] Socket.IO 무인증 핸드셰이크

```
GET /ws/?EIO=4&transport=polling → 200 OK
{"sid":"3Tku-CmqZid8QjajAAar","upgrades":["websocket"],...}
```

- 인증 없이 Socket.IO 세션 생성 가능
- 서버가 이벤트 수준에서 권한 검증하면 문제 없지만, 미검증 시 게스트로 로비 정보 등 접근 가능

---

## 4. 게임 구조 분석

### 4.1 Socket.IO 이벤트 맵

**플레이어 → 서버**:
| 이벤트 | 용도 |
|--------|------|
| `player:ready` | 준비 상태 토글 |
| `player:bet` | 베팅 (check/pping/quarter/half/ddadang/call/die) |
| `player:open` | 카드 공개 (cardId 지정) |
| `player:choosePair` | 페어 선택 |
| `player:show` | 카드 보여주기 |
| `player:joinRedeal` | 재딜 참여 |
| `player:emote` | 이모트 전송 |
| `player:wait` | 대기 시간 설정 |
| `room:join` | 방 입장 |
| `room:leave` | 방 퇴장 |

**서버 → 플레이어**:
| 이벤트 | 용도 |
|--------|------|
| `room:state` | **전체 게임 상태** (핵심) |
| `room:emote` | 이모트 수신 |
| `room:error` | 에러 메시지 |
| `room:left` | 퇴장 확인 |
| `lobby:rooms` | 로비 방 목록 |
| `me:profile` | 내 프로필 |
| `admin:alert` | 관리자 알림 |

### 4.2 베팅 구조

```
BET_LABELS = {
  check: "체크",  pping: "삥",     quarter: "쿼터",
  half: "하프",    ddadang: "따당",  call: "콜",
  die: "다이"
}
```

### 4.3 인증 흐름

1. 사용자 → Socket.IO 연결 (게스트 or devUserId)
2. 사용자 → `auth:login` (loginId, password, deviceId, clientHints)
3. 서버 → 토큰 반환
4. 클라이언트 → `sudda-now-token`에 저장
5. 재접속 시 토큰으로 자동 인증

---

## 5. 부정행위·조작 가능성 판단

### 가능성 있음 (검증 필요)

| 시나리오 | 조건 | 심각도 |
|----------|------|--------|
| **상대 패 엿보기** | room:state에 상대 카드 데이터 포함 시 | CRITICAL |
| **devUserId 관리자 사칭** | 서버가 devUserId를 프로덕션에서 수락 시 | CRITICAL |
| **크레딧 조작** | admin:adjustCredit 권한 검증 미흡 시 | CRITICAL |
| **게임 결과 조작** | admin:liveGames로 실시간 감시 + 개입 가능 시 | HIGH |

### 가능성 낮음 (서버 의존)

| 시나리오 | 이유 |
|----------|------|
| 카드 딜링 조작 | 딜링/셔플 로직 클라이언트에 없음 → 서버 측 처리 추정 |
| 베팅 액수 조작 | player:bet은 action만 전송, 금액은 서버 계산 추정 |
| RNG 시드 예측 | 클라이언트에 RNG/시드 관련 코드 없음 |

---

## 6. 권장 조치 (긴급도 순)

1. **[긴급] devUserId 제거** — 프로덕션 서버에서 devUserId 인증 경로 완전 제거
2. **[긴급] room:state 검증** — 상대 카드 데이터가 공개 전에 전송되지 않는지 확인
3. **[높음] 토큰 → HttpOnly 쿠키** — localStorage/sessionStorage 대신 HttpOnly Secure 쿠키 사용
4. **[높음] 관리자 JS 분리** — admin 청크를 인증된 관리자에게만 제공 (서버 측 라우트 보호)
5. **[중간] admin 이벤트 권한 검증** — 모든 admin: 이벤트에 서버 측 역할 검증 확인
6. **[중간] WebSocket 메시지 무결성** — player:bet 등의 이벤트 파라미터 변조 방지

---

## 7. 다음 단계

블랙박스 분석의 한계로 **핵심 질문이 미해결**:

1. `room:state`에 상대 카드 데이터가 포함되는가? → **인증 후 게임 참여하여 WS 패킷 캡처 필요**
2. `devUserId`가 프로덕션에서 작동하는가? → **Socket.IO 직접 연결로 확인 필요**
3. `admin:` 이벤트에 서버 측 권한 검증이 있는가? → **소스코드(화이트박스) 검토 필요**

계정 정보를 제공하면 인증 후 심층 테스트를 진행하겠습니다.
