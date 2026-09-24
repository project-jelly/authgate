# Spec 010: 업그레이드 & 하위 호환

## 개요

버전 간 **업그레이드 순서**와 **하위 호환이 깨지는(backward-incompatible) 변경**을 정리한다.
대부분의 릴리즈는 순서와 무관하게 올릴 수 있지만, 아래 항목은 정해진 순서를 지켜야 하고
일부는 배포 방식(롤링 금지 등)에 제약이 있다.

마이그레이션 자체는 authgate 시작 시 자동 적용된다 ([009 운영](009-operations.md) 참조).
이 문서는 "어떤 순서로, 어떤 주의로 버전을 올리는가"를 다룬다.

## Distroless 실행 이미지 전환

실행 이미지가 Alpine에서 Distroless static Debian 13으로 바뀐다.
비특권 사용자 UID/GID는 `65532:65532`다. 기존 사용자 소유로 제한된 signing key,
설정 및 brand 파일은 새 사용자도 읽을 수 있는지 확인한다. 작업 디렉터리 `/`와
마이그레이션 경로 `/migrations`, HTTP 엔드포인트 및 DB 스키마는 유지한다.

컨테이너 내부의 `sh`, `wget`, `apk`에 의존한 커스텀 healthcheck나 운영 스크립트는
사용할 수 없다. Docker/Compose는 `/authgate healthcheck`를 exec 형식으로 실행하고,
Kubernetes는 기존 HTTP probe를 사용한다. 기본 이미지에 디버깅 도구를 추가하지 않고
필요 시 별도 디버그 컨테이너로 조사한다.

## Migration 016 유지

v0.10.1은 v0.10.0의 MCP Device resource 바인딩을 되돌리지만 이미 적용된
`016_device_codes_resource` migration과 nullable 컬럼은 삭제하지 않는다. 기존 DB와
신규 설치의 migration 이력을 일치시키기 위한 것이며, 해당 컬럼과 번호를 재사용하지 않는다.

## PII 암호화 → 평문 제거 (2단계, 순서 필수)

PII 평문(email / name / provider_user_id)을 암호화 컬럼으로 옮기는 작업은 **두 릴리즈에 걸쳐**
적용된다. 순서를 지키지 않으면 평문 PII가 암호화되지 못한 채 컬럼이 사라져 복구 불가다.

```
[1단계] PII 암호화 릴리즈 (backfill 수행)        — 하위 호환 유지
   · 부팅 시 기존 평문을 암호화 + 평문 컬럼을 NULL로 비운다 (신규 컬럼만 추가)
   · backfill 완료 확인
            ↓  (count 둘 다 0 확인 후에만)
[2단계] 평문 제거(cleanup) 릴리즈                 — ⚠️ 하위 호환 깨짐
   · 평문 컬럼 + 구 평문 UNIQUE 제약을 DROP (migration 014). backfill 코드 제거,
     PII 키 필수화(keys-OFF fallback 제거)
```

### 1단계: PII 암호화 (backfill)

- 부팅 시 기존 평문(`email` / `name` / `provider_user_id`)을 암호화하고 평문 컬럼을 `NULL`로
  비운다.
- `DEV_MODE=false`면 PII 키 4개(`PII_ENC_ROOT_*`, `PII_LOOKUP_ROOT_*`)가 필수다.
- 배포 후 backfill 완료를 반드시 확인한다 (둘 다 `0`이어야 함):

  ```sql
  SELECT count(*) FROM users
    WHERE email_hash IS NULL AND email IS NOT NULL;
  SELECT count(*) FROM user_identities
    WHERE provider_sub_hash IS NULL AND provider_user_id IS NOT NULL;
  ```

- 이 단계는 **하위 호환을 깨지 않는다.** 신규 컬럼만 추가되고 평문 컬럼은 그대로 남으므로,
  이전 버전 바이너리와 공존해도 안전하다.

### 2단계: 평문 제거 (cleanup) — 하위 호환 깨짐

- 평문 컬럼(`users.email` / `users.name` / `user_identities.provider_user_id`)과 구 평문
  UNIQUE 제약을 DROP한다(**migration 014**). backfill 코드와 keys-OFF 평문 fallback이 함께
  제거되어 **PII 키가 항상 필수**가 된다. 계정 삭제 redaction은 평문 tombstone 대신 암호/해시
  컬럼을 `NULL`로 비우는 방식으로 바뀐다.
- **하위 호환이 깨지는 지점:**
  - 평문 컬럼을 참조하던 **이전 버전의 쿼리는 `column does not exist`로 실패**한다.
    롤링 배포로 구/신 바이너리가 공존하면 구버전이 깨진다.
    → 단일 인스턴스 교체(구버전 종료 → 마이그레이션 → 신버전 시작)로 배포한다.
  - DB를 외부(read-replica, 분석 파이프라인 등)와 공유 중이면 그쪽도 영향을 받는다.
- **전제 조건:**
  - 1단계 backfill이 100% 끝나 있어야 한다 (남은 평문 행이 있으면 영구 유실).
  - 평문 `email`을 쓰던 계정 삭제 tombstone(`deleted-<id>@deleted.invalid`)을 다른 방식으로
    먼저 옮겨야 한다.

## 규칙 요약

- 1단계를 거치지 않고 이전 버전에서 cleanup 릴리즈로 **직행 금지** (PII 유실).
- 1단계 배포 후 backfill count가 `0`이 아니면 cleanup으로 **넘어가지 않는다**.
- cleanup은 하위 호환을 깨므로 **롤링 배포 금지**, 단일 인스턴스 교체로 배포한다.
- **다운그레이드 불가:** cleanup 이후에는 평문 컬럼이 없으므로 이전 버전으로 롤백할 수 없다.
  되돌리려면 컬럼 복원 + 키로 복호화하여 평문 재생성이 필요하며 비권장이다.
