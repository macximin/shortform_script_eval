# shortform_script_eval

숏폼 대본 생성 결과를 독립적으로 비교·평가하는 DDD-lite repo다.

## Owns

- 벤치마크 입력 세트
- 평가 루브릭과 판정 계약
- 평가 실행 결과와 scorecard
- 평가 재현 영수증

생성 후보를 직접 고치거나 승인본으로 승격하지 않는다.

## Source-distance lane

권리 확인된 Reference comparison packet과 대본의 비식별 projection을 받아
다음을 계산한다.

- 최장 공통 문자열 길이
- 문자 n-gram 및 단어 shingle Jaccard
- 사건 sequence LCS 비율
- 보호 구문 직접 중복

생산 기본 임계값은 두지 않는다. 모든 실행은 버전과 calibration receipt hash가
있는 정책을 명시적으로 받아야 한다. 보호 구문 중복은 `fail`, 구조·어휘 지표
초과는 `review_required`, 그 외는 `pass` receipt를 내보낸다. receipt에는
원문이나 보호 구문 자체를 남기지 않는다.

## Calibration gate

`calibration`은 pass/review/fail이 모두 포함된 versioned benchmark에서 trial
policy를 실행하고 case별 기대 판정과 실제 판정을 hash-bound run으로 남긴다.

- 합성 dataset은 `synthetic_canary` 정책만 검증할 수 있다.
- production 승격은 `rights_cleared` dataset, 전 case 일치, exact run hash와
  owner approval receipt가 모두 필요하다.
- Foundry는 `production_approved` 정책 receipt만 기본 반입한다.

현재 repo에는 합성 fixture만 있고 실제 production 정책은 없다.
