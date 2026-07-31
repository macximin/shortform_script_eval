# Distance policy calibration contract v1

## 목적

임계값을 직감으로 production 기본값에 넣지 않는다. 버전이 고정된 benchmark,
trial policy, 실행 결과와 owner 승인 사이를 hash로 묶는다.

## Dataset

각 dataset은 다음을 고정한다.

- dataset id/version과 content hash
- Reference manifest hash
- `synthetic` 또는 `rights_cleared` tier
- pass, review_required, fail 기대 사례
- rights-cleared인 경우 dataset rights receipt hash

세 기대 판정 중 하나라도 빠지면 calibration dataset이 아니다.

## Run

CalibrationRunner는 모든 사례를 같은 trial policy와 Reference manifest로
평가한다. 각 결과는 기대 판정, 실제 판정, source-distance receipt hash를
남긴다. dataset이나 trial policy가 바뀌면 run hash가 바뀐다.

## Production promotion

다음 조건을 모두 충족해야 `production_approved` 정책을 만들 수 있다.

1. dataset tier가 `rights_cleared`
2. run이 정확한 dataset과 trial policy hash를 참조
3. 모든 기대 판정과 실제 판정이 일치
4. owner approval receipt가 정확한 run hash를 승인

합성 dataset은 구조 canary로만 쓴다. 실제 자료가 없으므로 현재 production
threshold와 production policy는 생성하지 않았다.
