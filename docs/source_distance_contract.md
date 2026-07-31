# Source-distance evaluation contract v1

## 역할

Eval은 대본을 쓰거나 고치지 않는다. Foundry가 내보낸 candidate projection과
Reference가 권리 확인한 comparison packet을 받아 독립 receipt만 만든다.

## 입력

- candidate id, 정규화 전 대본 projection, 사건 sequence
- reference packet id/version과 manifest hash
- 각 source의 비교 허용 권리 상태와 content/event/rights receipt hash
- runtime 대조에만 쓰는 source text, 사건 sequence, 보호·허용 구문
- policy id/version과 calibration receipt hash

Reference manifest hash가 runtime 입력에서 재계산한 값과 다르면 평가하지 않는다.

## 지표와 판정

- 최장 공통 문자열 길이
- 문자 n-gram Jaccard
- 단어 shingle Jaccard
- 사건 sequence LCS 비율
- 허용되지 않은 보호 구문 직접 중복

보호 구문 중복은 `fail`이다. 다른 지표가 정책 임계값을 넘으면
`review_required`이며 자동 실패로 해석하지 않는다. 어떤 임계값도 코드의
생산 기본값으로 제공하지 않는다. 정책은 반드시 버전과 calibration receipt
hash를 가져야 한다.

## 출력

receipt에는 candidate projection, reference manifest, 정책·보정 hash, source
id별 지표와 trigger code만 남긴다. 원문, locator, 보호 구문 자체는 남기지
않는다. receipt는 생성 후보를 수정하거나 승인하지 않는다.

현재 테스트 정책과 source는 모두 합성 fixture이며 production 기준이 아니다.

## 정책 tier

- `synthetic_canary`: 계산·handoff 규격 시험 전용
- `production_approved`: 권리 확인 dataset의 calibration run과 owner approval을
  정확히 잇는 정책

합성 dataset은 owner가 승인해도 production 정책으로 승격할 수 없다.
