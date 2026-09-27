# authgate — 개발 규칙

## 문서 싱크 규칙

코드를 바꿀 때 아래 문서를 **같이** 바꿔야 한다.
"나중에 문서 업데이트"는 없다. 코드 PR과 문서 수정은 한 커밋에 들어간다.

| 코드 변경 | 같이 바꿔야 하는 문서 |
|-----------|----------------------|
| 환경변수 추가/변경/제거 | `docs/spec/009-operations.md` 환경변수 표 |
| 마이그레이션 파일 추가 | `docs/spec/009-operations.md` 초기 설정 섹션 |
| 엔드포인트 추가/변경 | 해당 `docs/spec/00N-*.md` |
| 상태기계 변경 (`user.Status` 등) | `docs/adr/000-authgate-identity.md` |
| 테스트 파일 추가/제거 | `docs/tests/README.md` |
| 패키지 구조 변경 | `docs/architecture/*.md` |

## 문서 계층과 역할

```
ADR (docs/adr/)
  → 정책/철학. 코드보다 먼저 쓴다.

Spec (docs/spec/)
  → 외부 계약 + 상태기계. 엔드포인트/플로우 변경 시 동시 수정.

Architecture (docs/architecture/)
  → 패키지 경계와 책임. 구조 변경 시 동시 수정.

Operations (docs/spec/009-operations.md)
  → 현재 배포/운영 현실. 코드와 항상 일치해야 한다.

Tests docs (docs/tests/)
  → 구현된 테스트의 설계 계획. 테스트 추가 후 반영.
```

## 진실원천 (Source of Truth)

- 정책: ADR
- 외부 계약: Spec
- 현재 운영: Operations (009)
- 구현 현실: 코드
- 테스트 현실: `*_test.go` 파일

문서가 코드와 충돌하면 → **코드가 맞다**. 문서를 고친다.
코드가 ADR/Spec과 충돌하면 → **의도적인 변경인지 확인 후 결정**한다.

## 테스트

```bash
# 일반 유닛 테스트 (Docker 불필요)
go test ./...

# 통합 테스트 (Docker 필요, testcontainers-go)
go test -tags=integration ./...
```

## 릴리즈

버전은 `VERSION` 파일 하나로 관리한다. `VERSION` 파일이 main에 머지되면 `release.yml`이 자동으로 나머지를 처리한다.

### 릴리즈 순서

```bash
# 1. 릴리즈 브랜치 생성
git checkout main && git pull
git checkout -b release/vX.Y.Z

# 2. VERSION 파일 수정
echo "X.Y.Z" > VERSION

# 3. 커밋 + PR
git add VERSION
git commit -m "chore(release): bump version to vX.Y.Z"
git push -u origin release/vX.Y.Z
# GitHub에서 PR 생성 → 머지
```

### 머지 후 자동 실행 (release.yml)

1. 성공한 main push CI의 정확한 SHA와 미발행 `VERSION` 확인
2. 멀티 아키텍처 후보 이미지 1회 빌드 (SBOM/provenance 포함)
3. amd64/arm64 digest를 Trivy로 검사하고 attestation 검증
4. 검사한 index digest를 `vX.Y.Z` / `latest`로 승격한 뒤 git 태그와 GitHub Release 생성

수동 릴리스 우회는 없다. 재시도는 성공한 CI에 연결된 Release 실행을 다시 실행한다.
이미 발행된 버전은 건너뛴다. 이미지의 하위 manifest와 attestation 보존을 위해
GHCR 자동 삭제는 수행하지 않는다. 세부 정책은 `docs/spec/009-operations.md`를 참조한다.

### 버전 규칙

- `patch` (X.Y.**Z**): 버그 수정, 의존성 보안 패치
- `minor` (X.**Y**.0): 새 기능 추가 (하위 호환)
- `major` (**X**.0.0): 파괴적 변경 (API/DB 스키마 등)
