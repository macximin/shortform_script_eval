# DDD-lite boundary

버전이 고정된 대본 packet을 받아 버전이 고정된 rubric으로 평가한다. 결과는
scorecard와 receipt로 내보내며 생성 후보와 승인 상태를 직접 변경하지 않는다.

Source-distance 평가는 Reference가 권리 확인한 runtime packet을 소비하지만
원천 정본을 소유하지 않는다. Foundry에는 원문 없이 후보 projection hash,
reference manifest hash, 정책·보정 hash, 지표와 판정만 수동 전달한다.
