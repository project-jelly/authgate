# 인증 코어 리팩토링 종료 기준

기준: v0.10.11 (`4bd3149`), 2026-09-19. 아래 범위의 코드·테스트 계약이며 전체
OAuth/OIDC 보안 인증이나 운영 배포 완료를 뜻하지 않는다.

## 변경 단위와 원칙

1. [PR 391](https://github.com/project-jelly/authgate/pull/391): 인증 코드의 조건부 일회성 소비.
2. [PR 392](https://github.com/project-jelly/authgate/pull/392): access-token 용도/profile 검증과 UserInfo scope.
3. [PR 393](https://github.com/project-jelly/authgate/pull/393): refresh 소비·발급·폐기 transaction과 관련 scope/오류 계약.

이 순서로 검토한다. 마지막 변경의 CI는 앞선 변경을 포함한 조합을 검증한다.
zitadel provider, 기존 Storage facade와 sqlc를 유지한다. 디렉터리 크기 대신
재현된 결함을 우선하며, 새 package/interface/table 없이 필요한 검증 adapter와
transaction 경계만 보완한다. 관련성이 없는 파일 이동·범용 framework는 범위 밖이다.

## 표준 추적 표

| 근거 | 구현 결정 | 회귀 증거 |
|---|---|---|
| [RFC 6749 §4.1.2–4.1.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2) | provider 검증 뒤 code 소비, refresh와 같은 tx | `TestIntegration_AuthCodeConcurrentOneShot`, `TestIntegration_InvalidCodeRequestPreservesCode`, `TestIntegration_AuthCodeConsumptionRollsBackWithGrant` |
| [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) | client/scope 검증 전 소비 없음, 새 refresh는 원본 scope 보존 | `TestIntegration_InvalidRefreshRequestPreservesGrant`, `TestIntegration_RefreshNarrowingPreservesOriginalGrantScope`, `TestIntegration_RefreshInsertFailureRollsBackConsumption` |
| [RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2) | public client 재사용 즉시 family 폐기, 관계/tombstone/감사 보존 | `TestIntegration_PublicRefreshReplayIgnoresGrace`, `TestIntegration_RefreshReuseDetection_FamilyRevokesDescendants`, `TestAudit010And011_ReuseOfRevokedFamilyRecordsEachPresenter` |
| [RFC 7009 §2.1–2.2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1) | client에 결합된 grant 폐기, 발급과 family 잠금 공유, DB 실패를 성공으로 응답하지 않음 | `TestRefreshAndRevokeSerializeAcrossStorageInstances`, `TestRefreshReuseGrace_RevokeByAnotherClientLeavesGrantAlive`, `TestIntegration_RevokeBackendFailureIsNotSuccess` |
| [RFC 8725 §3.12](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12), [RFC 9068 §2/4](https://www.rfc-editor.org/rfc/rfc9068.html#section-4) | JWT 용도 구분, RS256·issuer·서명·만료·필수 claims·대상 검사 | `TestIntegration_UserinfoAccessTokenProfile`, `TestIntegration_IntrospectionRequiresAccessTokenAndOwningClient`, `TestProviderRoutes_UserinfoWithRealProvider`, 기존 `TestIDTokenAtHashMatchesRewrittenAccessToken` |
| [OIDC Core §5.3–5.4](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) | 검증된 access scope로만 신원 필드 선택 | `TestIntegration_UserinfoUsesRefreshedScopes`, `TestTokenCallbacksRequireVerifiedClaims` |
| [RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1) | token route에서 성공·provider/resource 오류·429에 캐시 금지 적용, 토큰 재서명 뒤에도 유지 | `TestProviderRoutes_TokenResponsesAreNotCacheable` |
| [RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2), [RFC 9207 §3](https://www.rfc-editor.org/rfc/rfc9207.html#section-3) | 두 discovery 경로에 실제 지원 capability와 iss/CIMD 정책 광고, library OIDC 필드 보존 | `TestOAuthMetadataRoutes_ShareCapabilitiesAndPreserveProviderDiscovery` |

## 호환성과 SHOULD 판단

- 인증 코드 재사용 시 이전 발급 토큰 폐기는 RFC 6749의 SHOULD다. 이번 변경은
  code row를 삭제하고 code→grant 관계를 추가 저장하지 않는다. 이전 grant를
  찾아 폐기하는 기능과 stateless access-token 차단 목록은 도입하지 않았다.
  최대 한 번의 발급과 재사용 거부는 보장하지만 이 SHOULD는 미채택으로 남긴다.
- Public client(CIMD/MCP 포함)는 5초 유예를 더 이상 사용하지 않는다. client가
  갱신을 직렬화해야 한다. 인증된 static confidential client만 기존 5초/최대
  3 child 유예를 사용할 수 있다. 이는 로컬 호환 정책이며 모두에게 엄격한
  재사용 탐지를 제공한다는 의미가 아니다.
- 정상 `at+jwt` 토큰은 계속 유효하다. 과거 fallback으로 발급된 `typ=JWT`
  access token은 거절하므로 재인증이 필요하다.
- UserInfo는 AuthGate의 일반 OIDC audience(`client_id`)를 받으며 외부 API용
  resource-bound token은 받지 않는다. openid-only에서 sub만 공개하는 것은
  AuthGate의 최소 공개 정책이다.
- DB가 transaction을 abort한 경우와 commit 뒤 서명/HTTP 실패는 다르다. 후자는
  소비를 되돌리지 않는다. COMMIT 응답 유실은 성공 여부가 불명확하여 재시도 성공을
  보장하지 않는다. 토큰 응답 재전송 저장소는 추가하지 않는다.
- 기존 stateless access token의 남은 수명, 새 grant 발급 차단, 릴리즈,
  배포와 운영 실호출은 서로 다른 상태다.

## 종료 조건

- 위 다섯 재현 결함(code 동시 교환, ID-token 대체, scope 누출, 잘못된 refresh
  요청의 소비, revoke 뒤 child 발급)의 회귀 테스트가 통과한다.
- 표의 적용 대상 계약과 코드가 일치하고 SHOULD/호환 정책 판단이 기록된다.
- Browser/Device/MCP 로그인·계정 상태·resource binding·logout 기존 통합 테스트를 유지한다.
- 최종 조합 SHA에서 CI의 Test/Race/Vet/Lint/SQLC/Format/Vulnerability 검사가 통과한다.
- 이 범위에 직접 연결된 재현 실패가 없으면 종료한다. 줄 수나 디렉터리 크기는
  추가 리팩토링의 근거가 아니다. 결과는 PR의 CI에서 확인한다.
