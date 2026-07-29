# DIBE: Dynamic Incremental Binary Editing

*Language: [English](README.md) | **한국어***

DIBE는 **이미 실행 중인** x86-64 리눅스 프로세스의 기계어 코드를 그 자리에서
패치합니다. 프로세스를 멈추거나 재시작할 필요가 없고, 대상 프로그램이 특별한
지원을 갖춰 빌드되어 있을 필요도 없습니다. 모든 패치 비용은 해당 명령어를
실행 중인 단일 스레드로만 국한되며, 프로세스 전체를 멈추는 전역 정지는 결코
발생하지 않습니다.

이를 위해 작업을 둘로 나눕니다. 오프라인 **admin** 프로세스가 [E9Patch](https://github.com/GJDuck/e9patch)를
수정한 포크를 재사용해 *무엇을* 바꿔야 하는지(트램폴린 배치, 패치 전술, 여러
지점을 동시에 수정해야 하는 경우의 적용 순서)를 메타데이터로 계산해 두고,
`LD_PRELOAD`로 적재되는 가벼운 프로세스 내부 **runtime**이 그 계획을 정렬
특성을 활용한 원자적 덮어쓰기(atomic overwrite)로 실행 중인 프로세스에
재현합니다.

## 빠른 시작 (Quickstart)

```bash
git clone <this-repo> && cd dibe
make -j                        # patcher.so, 툴체인, E9Patch 빌드
./examples/quickstart/run.sh   # 실행 중인 일반 프로세스를 실시간으로 패치
```

`examples/quickstart/run.sh`는 필요하면 툴체인을 빌드하고, 작은 장기 실행
프로그램을 시작한 뒤, 이를 역어셈블하여 모든 jump/branch 지점을 포함하는 패치
계획을 생성하고, 이를 *실행 중인* 프로세스에 적용한 다음, DIBE 자신이 수행한
바이트 단위 검증 결과를 출력합니다:

```
[quickstart] === patcher.so report (from the live process) ===
  [patcher] S0 count: 9
  [patcher] S1 count: 1
  [patcher] int3 count: 0
  [validate] === ALL PASSED ===

[quickstart] SUCCESS: every overwritten byte in the running process was read back and verified.
```

quickstart는 패치 기구 자체를 동작시키고 바이트가 정확히 적용되었음을
증명하지만, 그 패치들은 의도적으로 동작에 영향을 주지 않습니다. 패치가 실행 중인
프로세스의 *동작을 실제로 바꾸는* 모습을 보려면
[`examples/live-fix/`](examples/live-fix/)를 참고하세요. 작은 서비스가
`next_tick()`의 버그 때문에 `tick=0`에 멈춰 있는 상태에서, DIBE가 그 함수를 그
자리에서 고칩니다. 동일한 프로세스가(PID도 그대로이고, 멈추거나 재시작한 적도
없이) 카운트를 시작합니다:

```bash
./examples/live-fix/run.sh
```

```
[live-fix] === before the patch (the bug: stuck at tick=0) ===
  tick=0
  tick=0
[live-fix] === after the patch (same PID 274601, never restarted) ===
  tick=1
  tick=2
  [patcher] S0 count: 1
  [validate] === ALL PASSED ===
```

## 동작 원리

- **오프라인 계획 수립, 온라인 활성화(Offline planning, online activation).**
  무거운 분석(디스어셈블리, 제어 흐름 추론, 트램폴린 배치)은 모두 admin
  프로세스에서 오프라인으로 이루어집니다. 프로세스 내부 runtime은 이미 결정된,
  사전 검증된 연산만을 수행하며 그 자체로는 어떤 계획 수립 로직도 갖지 않습니다.
- **정렬 특성을 활용한 원자적 덮어쓰기(Alignment-aware atomic overwrites).**
  대상 지점이 제공하는 정렬 보장에 따라 세 가지 전략 중 하나로 패치를
  적용합니다: **S0**(8바이트 정렬 단일 저장), **S1**(16바이트 `CMPXCHG16B`),
  **S2**(원자성 보장이 없는 지점을 위한 `INT3` 게이트 방식의 2단계 폴백).
  S0/S1은 동시 실행 중인 스레드에게 전혀 보이지 않으며, S2만이 게이트에 걸린
  단일 스레드를 순간적으로 지연시킬 수 있습니다.
- **안전한 다중 지점 활성화(Safe multi-site activation).** 일부 패치 전술은
  둘 이상의 명령어를 함께 다시 씁니다(예: jump를 위한 공간을 확보하기 위해
  인접 명령어를 축출하는 경우). admin 프로세스는 이런 수정들 사이의 의존
  순서를 오프라인에서 미리 계산해(축출 대상을 먼저 처리) 메타데이터로
  내보내므로, runtime은 동시 실행 중인 스레드가 관찰하는 모든 중간 상태가
  항상 올바른 순서로 패치를 적용하며, 패치 시점에는 순서를 판단하는 로직이
  전혀 실행되지 않습니다.
- **충돌 없는 트램폴린 매핑(Conflict-free trampoline mapping).** 트램폴린
  페이지는 `memfd` + `SCM_RIGHTS` + `MAP_FIXED_NOREPLACE`를 통해 대상
  프로세스의 살아있는 주소 공간에 배치됩니다. 충돌(`EEXIST`)이 발생하면
  재계획하거나 깔끔하게 중단하며, 배치 문제를 해결할 수 없는 경우 살아있는
  코드는 결코 건드리지 않습니다.

## 아키텍처

```
+-----------------------------+     +-----------------------------------+
|   Admin (scripts/patch.sh)  |     |   대상 프로세스 (Target process)   |
|                             |     |   (LD_PRELOAD=patcher.so)          |
|  micro_patch.json           |     |                                    |
|       |                     |     |  +--------------+                 |
|       v                     |     |  | Mapping       | <- mmap        |
|  patch_to_req -> req.json   |     |  | server        |    trampoline  |
|       |                     |     |  | (UNIX socket) |    pages       |
|       v                     |     |  +--------------+                 |
|  e9patch (modified)         |     |                                    |
|       |                     |     |  +--------------+                 |
|       +-> jmp.jsonl --------+-->--+  | Activation    | <- atomic jmp |
|       +-> patches.jsonl ----+-->--+  | thread        |    overwrites  |
|       +-> resp.json         |     |  +--------------+                 |
|                             |     |                                    |
|  FIFO: "APPLY" -------------+-->--+  FIFO control thread               |
+-----------------------------+     |  (/tmp/dibe_ctrl.<PID>)            |
                                     |                                    |
                                     |  INT3 trap handler (S2 fallback)   |
                                     +-----------------------------------+
```

**Admin 측** (`scripts/patch.sh`): 패치 명세(`micro_patch.json`)를 E9Patch
호환 요청으로 변환하고, 수정된 E9Patch를 실행하여 재작성 메타데이터를 생성한
뒤, 대상 프로세스에 적용하라는 신호를 보냅니다.

**Target 측** (`patcher.so`): 시작 시 `LD_PRELOAD`로 적재되며,
`__attribute__((constructor))`를 사용합니다(glibc 2.34+와 호환되며,
`__libc_start_main` 후킹 방식과 달리 문제가 없습니다). 트램폴린 페이지 할당을
위한 매핑 서버와, S0/S1/S2를 사용해 jump 덮어쓰기를 적용하는 활성화 스레드를
실행합니다.

## 저장소 구조

```
src/               runtime + admin 측 소스
  patcher.cpp          프로세스 내부 runtime (-> LD_PRELOAD로 적재되는 patcher.so)
  patch_to_req.cpp     micro_patch.json -> req.json 변환기
  dlopen.cpp           APPLY/COMMIT 제어용 시그널 송신기
  generate_patches_from_objdump.py   objdump -d 출력으로부터 패치 계획 자동 생성
include/           벤더링된 헤더 (nlohmann/json)
scripts/
  patch.sh             오케스트레이터: 대상 PID를 확인하고 파이프라인을 구동
third_party/
  e9patch/             수정된 E9Patch 포크, 오프라인 메타데이터 생성기로 재사용
examples/
  quickstart/          바로 실행 가능한 데모: 모든 jmp/jcc 지점을 패치하고 검증 (target.c + run.sh)
  live-fix/            실행 중인 프로세스의 버그를 고치고 출력이 바뀌는 것을 확인
tests/               단위 + 통합 테스트 (make test, smoke_suite.sh)
docs/                가이드 및 아키텍처 노트
```

빌드 산출물(`patcher.so`, `e9patch`, `patch_to_req`, `dlopen`,
`target_program`)은 소스 위치와 무관하게 항상 저장소 루트에 생성됩니다. 전체
스크립트/산출물 의존 관계는 [`docs/guides/scripts.md`](docs/guides/scripts.md)를
참고하세요.

## 의존성

- C++17 컴파일러 (`g++`)
- `nlohmann/json` (`include/json.hpp`로 벤더링됨)
- `libdl`, `pthread`
- 벤더링된 E9Patch 포크는 추가로 `libdw`, `libZydis`가 필요합니다(또는
  `third_party/e9patch/` 안에서 `make dev`로 벤더링된 contrib로부터 빌드),
  `xxd`도 필요합니다.

## 빌드

```bash
make                    # 전체: patcher.so, patch_to_req, dlopen,
                         # target_program, 벤더링된 E9Patch 포크
```

개별 컴포넌트만 빌드하려면:

```bash
make patcher.so         # runtime 패처 라이브러리
make patch_to_req       # patch-to-request 변환기
make dlopen             # 시그널 송신 유틸리티
make target_program     # quickstart용 테스트 대상 바이너리
make e9patch             # 벤더링된 E9Patch 포크 (third_party/e9patch/에 위임)
```

## 실행 중인 프로세스 패치하기

```bash
scripts/patch.sh <target_binary> <micro_patch.json> <patch_label> [<PID>|--auto]
```

`micro_patch.json`은 무엇을 패치할지 지정합니다. 아래는
[`examples/live-fix/`](examples/live-fix/)가 실제로 적용하는 계획으로, 2바이트
크기인 `next_tick()`의 본문을 `mov %edi,%eax; add $0x1,%eax; ret`, 즉
`return t + 1`로 교체합니다:

```json
{
  "patches": [
    {
      "patch_address": "1224",
      "target_length": 2,
      "patch_bytes": ["0x89", "0xf8", "0x83", "0xc0", "0x01", "0xc3"]
    }
  ],
  "pid": 12345
}
```

- `patch_address` — `objdump -d`가 출력하는 해당 지점의 주소. 이는 링크 시점
  주소이며 실행 시점 주소가 아닙니다. DIBE가 이를 파일 오프셋으로 변환한 뒤
  실행 중인 프로세스에 맞게 재배치하므로, ASLR이나 PIE를 여기서 따로 처리할
  필요가 없습니다.
- `target_length` — 해당 주소에 있는 명령어의 **바이트 단위** 길이 (위의
  `mov %edi,%eax`는 2바이트). 명령어의 *개수*가 아닙니다.
- `patch_bytes` — 트램폴린의 본문, 즉 그 명령어 대신 실행될 내용입니다. 원시
  바이트와 함께 다음 네 가지 토큰을 사용할 수 있습니다:

  | 토큰 | 확장되는 내용 |
  |-------|------------|
  | `$instr` | 원본 명령어 |
  | `$bytes` | 원본 명령어의 원시 바이트 |
  | `$break` | 해당 지점 다음 명령어로 돌아가는 jump |
  | `$take` | 분기 목적지로 가는 jump |

  `$break`로 끝나는 트램폴린은 원래 흐름으로 복귀하며, 이 덕분에
  `["0x90", "$instr", "$break"]`가 동작에 영향을 주지 않는 프로브가 됩니다.
  반면 위의 계획은 `ret`(`0xc3`)로 끝나므로 호출자에게 곧바로 복귀하고, 원본
  함수의 나머지 부분은 아예 실행되지 않습니다.

계획을 직접 작성하는 대신 자동 생성하려면:

```bash
objdump -d -w target_program > objdump.txt
python3 src/generate_patches_from_objdump.py -i objdump.txt -o micro_patch.json --pid <PID>
```

생성기는 `patches` 옆에 `instructions` 배열도 함께 내보냅니다. 이는 `.text`의
조밀한(dense) 디스어셈블리로, E9Patch가 트램폴린 전술의 기반이 되는
선행/후행 명령어 분석을 수행하는 데 필요합니다. **직접 작성한 계획에도 이
배열이 필요합니다.** 실무적인 방법은 `examples/live-fix/run.sh`가 쓰는
방식으로, 생성기가 계획을 만들게 한 뒤 `instructions`는 그대로 두고 `patches`
배열만 원하는 내용으로 교체하는 것입니다.

## 환경 변수

| 변수 | 설명 |
|----------|--------------|
| `DIBE_PIDFILE` | 조정을 위해 PID 파일을 기록할 경로 |
| `DIBE_START_GATE` | `1`이면 패치가 완료될 때까지 `main()`을 막습니다 (게이트가 열리면 해제됨) |
| `DIBE_VALIDATE` | 설정하면 적용 후 패치를 검증합니다 (바이트 단위 정확성 검사; 성능 측정 시에는 사용하지 마세요) |
| `DIBE_FORK_WORKERS` | `1`이면 fork된 자식 프로세스가 각자 자신의 FIFO + 매핑 서버를 갖습니다 (멀티 프로세스 서버용) |
| `DIBE_LIVE_PATCH` | `1`이면 대상이 실행 중인 상태로 패치합니다 (`START_GATE` 없음) |
| `DIBE_FORCE_S2` | 진단용 (기본 꺼짐). `1`이면 모든 덮어쓰기를 S2 `INT3` 게이트 경로로 강제합니다 |
| `DIBE_S2_DEBUG_DELAY_US` | 진단용 (기본 꺼짐). S2 게이트 윈도우를 인위적으로 넓혀 데모에서 결정적으로 재현되게 합니다(마이크로초 단위) |
| `DIBE_FORK_QUIESCE` | Fork 강화 (기본 꺼짐). `1` = `pthread_atfork` prepare-quiesce; `2` = 순수 `clone()`에 대한 seccomp/SIGSYS 트랩도 함께 설치 |

## 검증 모드

DIBE는 패치 적용 후 패치된 메모리를 읽어 계획과 바이트 단위로 비교하는 검증
모드를 제공합니다. 이는 정확성 검증 전용이며, 성능 측정 중에는 활성화하지
마세요.

```bash
DIBE_VALIDATE=1 scripts/patch.sh target_program micro_patch.json patched --auto
```

검증은 모든 트램폴린 페이지가 매핑되어 있는지, 그리고 `patches.jsonl`(트램폴린
바이트)과 `jmp.jsonl`(jump 덮어쓰기)의 모든 항목이 실제 메모리와 일치하는지
확인합니다. `/tmp/dibe_validate` 파일을 생성해 실행 중인 프로세스에서 검증을
트리거할 수도 있습니다 (환경 변수를 `main()` 이전에 정리하는 대상 프로그램에
유용합니다).

## 테스트

```bash
tests/smoke_suite.sh --build     # 다시 빌드한 뒤 모든 검사 실행
tests/smoke_suite.sh toolchain   # 이름이 지정된 검사 하나만 실행: toolchain, fork, unit, p3
make test                        # C/Python 단위 테스트만 실행
```

통합 검사는 `DIBE_VALIDATE=1`로 실제 패치를 적용하므로, 조용히 실패하는
적용 버그도 이 단계에서 걸러집니다. 단위 테스트(`make test`)는 다음을
다룹니다:

- `tests/test_fork.c` — `pthread_atfork`가 `fork()` 이후 워커별 FIFO를
  생성하는지 검증
- `tests/test_generate_patches.py` — jump 니모닉 판별, objdump 파싱,
  서브샘플링
- `tests/test_int3avoid_unit.c` — INT3 회피 플래너의 핵심 판단 로직
- `tests/p3_test.sh` — 합성 픽스처에 대한 predecessor-redirection 종단 간
  동작 검증

## 알려진 이슈

- **glibc 2.34+**: 전통적인 `__libc_start_main` 후킹 방식은 glibc 2.34+와
  호환되지 않습니다 (내부 시그니처가 변경됨). DIBE는 대신
  `__attribute__((constructor))` + `atexit`를 사용합니다.
- **C로 작성된 대상 프로그램**: `patcher.so`는 C++로 빌드되지만 `LD_PRELOAD`를
  통해 순수 C 프로그램에 흔히 적재됩니다. constructor 시점에 실행되는 코드는
  모두 `std::cerr`가 아니라 `fprintf`/POSIX 호출을 사용합니다. constructor가
  실행되는 시점에는 iostream이 아직 초기화되지 않았을 수 있기 때문입니다.

## 라이선스

GPLv3 ([`LICENSE`](LICENSE) 참고) — DIBE의 admin/runtime 코드는 이 프로젝트가
의존하는 벤더링된 E9Patch 포크(`third_party/e9patch/`, 자체 upstream GPLv3
라이선스 파일을 유지)와 동일한 라이선스로 제공됩니다.

UNIST(울산과학기술원)에서 개발되었습니다.
