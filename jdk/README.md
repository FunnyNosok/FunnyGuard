# Рерайт JDK — защита классов на уровне рантайма

Максимальный уровень защиты: расшифровка классов вшита **внутрь самой JVM**, а не в
JVMTI-агент. Агент можно снять (`-agentpath` убирается из командной строки) или
задетектить; здесь расшифровка живёт в `jvm.dll`, а закалка — в `java.base`. Отдельный
агент больше не нужен.

Это надстройка над основным проектом: формат зашифрованного класса (`jarhook`) тот же —
`PMCH` + version + IV(12) + ciphertext + GCM tag(16), AES-256-GCM, PBKDF2-HmacSHA256
(210000 итераций), ключ = XOR трёх вшитых частей + пароль. Контейнеры от `packer jarhook`
читаются и агентом, и пропатченным JDK без изменений.

> Sealed v3: `pmchDecrypt.cpp` теперь держит и sealed-путь — `PMCH` + `0x03` +
> `FILE_SALT(16)` + `CLASS_SEED(16)` + `IV(12)` + ct + tag, ключ `FILE_KEY` из
> `PMCH_SEAL` (hex 32Б, кладёт `SealedLauncher` в env дочернего процесса),
> `kmix = HMAC-SHA256(FILE_KEY, OpaquePredicate.digest(salt, seed))`. Legacy-гейт
> принимает version 1 и 2 (Java-пакeр пишет 2). После правок **пересобери**
> `exploded-image` — иначе в `jvm.dll` останется старый декриптор без v3.

## Что патчится

Два слоя, оба проверены на живой сборке (OpenJDK 21.0.13, MSVC 2022, Windows x64).

### Слой 1 — HotSpot (C++), расшифровка в движке
- `new-files/hotspot/pmchDecrypt.cpp` + `pmchDecrypt.hpp` — самодостаточный модуль:
  AES-256-GCM + PBKDF2 + base64 через **Windows CNG (bcrypt)**, линковка через
  `#pragma comment(lib, "bcrypt.lib")` (make-файлы не трогаются, HotSpot сам подхватывает
  новые `.cpp` в каталоге). Ключ выводится один раз (thread-safe), пароль берётся из
  окружения `PMCH_PASS`.
- `patches/classFileParser.cpp.patch` — в конструкторе `ClassFileParser` до начала
  разбора: если байты класса начинаются с `PMCH`, они расшифровываются в память, и
  подменяются и локальный `stream`, и член `_stream` (важно: `parse_linenumber_table`
  читает именно `_stream`). Класс без магии идёт по быстрому пути без изменений.

### Слой 2 — java.base, закалка рантайма
- `new-files/java.base/PmchGuard.java` (`jdk.internal.misc.PmchGuard`) — при старте:
  выключает self-attach, надёжно детектит `-agentlib:jdwp` / `-javaagent` / `-agentpath`
  через `jdk.internal.misc.VM.getRuntimeArguments()` (командная строка на Windows часто
  пустая, поэтому используется именно VM-аргументы). Политика через `PMCH_GUARD`:
  `OFF` / `LOG` (по умолчанию) / `EXIT` (halt при детекте).
- `patches/System.java.patch` — вызов `PmchGuard.enforce()` в конце
  `System.initPhase3()`, в защищённом try/catch (не может сломать загрузку).

## Как воспроизвести сборку

Требуется: **VS 2022 Build Tools (C++)**, **полный JDK 21** как boot JDK, **CMake**,
**MSYS2** с `autoconf make tar zip unzip` (см. корневой README проекта — там ставится
весь тулчейн).

```bash
git clone --depth 1 https://github.com/openjdk/jdk21u.git jdk-src
```

Применить патчи (из этой папки):

```bash
pwsh -File apply.ps1 -JdkSrc <путь к jdk-src>
```

Сконфигурировать и собрать разложенный образ (в MSYS2-шелле):

```bash
cd jdk-src
export TMP="C:\\Users\\<you>\\AppData\\Local\\Temp"   # иначе линкер jvm.dll падает LNK1104
export TEMP="$TMP"                                     # (пишет temp в C:\WINDOWS без прав)
bash configure --with-boot-jdk=<путь к JDK 21> --with-jvm-variants=server \
  --with-native-debug-symbols=none --disable-warnings-as-errors \
  --with-jvm-features=-vm-structs
make exploded-image CONF=windows-x86_64-server-release JOBS=4   # JOBS=4: меньше жрёт память
```

Как реально устроена закалка (проверено сборкой, а не по статье):

- **Отказ от агентов / module-override / Xshare:dump — безусловный в коде**, не за
  гейтом `!INCLUDE_JVMTI`. `patches/arguments.cpp.patch` ставит `#if 1`-отказы прямо
  в `parse_each_vm_init_arg`, поэтому они срабатывают при **включённом** JVMTI:
  `-agentlib:`/`-agentpath:`/`-Xrun`/`-javaagent` → «Agents/Instrumentation agents are
  not supported», `--patch-module=`/`--upgrade-module-path=` → «Module override is not
  supported», `-Xshare:dump` → «Shared archive dumping is not supported». VM не стартует.
  Почему так, а не `-jvmti`: **JFR жёстко зависит от JVMTI и SERVICES** на линковке
  (`jfrJvmtiAgent`/`jfrPeriodic` тянут `JvmtiAgentList`, `JvmtiEnvBase`, `ObjectCountEventSender`).
  Отключение `-jvmti`/`-services` заставляет отключать и `-jfr`, а это тянет дальше
  (dcmd/type-writer'ы JFR). Комбо `-jvmti,-services,-vm-structs` (с `jfr`) **не собирается**.
  Безусловные отказы дают тот же эффект для клиента без каскада фич.
- **attach/jcmd** блокируется рантайм-флагом `-XX:+DisableAttachMechanism` (его передают
  все лаунчеры), а не вырезанием `-services`. Проверено: `jcmd <pid>` →
  `AttachNotSupportedException: The VM does not support the attach mechanism`.
- `-vm-structs` → `INCLUDE_VM_STRUCTS=0`: `vmStructs.cpp` исключён, символов
  `gHotSpotVMStructs/Types/IntConstants/LongConstants` в `jvm.dll` нет (проверено
  `dumpbin /exports`: 0 против 4 в ванильном JDK) — SA/`jhsdb`/`jmap -F` слепнут.
  Единственная снятая фича; `jvmti`, `services`, `jfr`, `management`, оба компилятора — на месте.
- Дополнительно `PmchGuard` (java.base) детектит агентов в рантайме через
  `VM.getRuntimeArguments()` — второй рубеж поверх безусловных отказов.

Дополнительно все лаунчеры (`scripts/run-protected.ps1`, `scripts/run-sealed.ps1`,
`license/scripts/secure-launch.ps1`, `memory-launch.ps1`, `SealedLauncher`-потомок)
стартуют JVM с `-XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading`
(оба флага есть в `globals.hpp` дерева безусловно).

Готовый рантайм: `jdk-src/build/windows-x86_64-server-release/jdk/` (`bin/java.exe`).

> `make images` дополнительно пакует `src.zip` через `mklink /J` и на Windows без
> developer mode падает с Error 127 — для рабочего рантайма это не нужно, используйте
> `exploded-image`.

## Как запускать защищённый клиент

Классы шифруются штатным упаковщиком проекта (`packer jarhook`, см. корневой README),
пароль передаётся движку через окружение:

```bash
set PMCH_PASS=<пароль>
java -cp client-hooked.jar com.protectedclient.example.ClientMain
```

Никакого `-agentpath` — расшифровку делает сам JDK.

## Проверка hardened-сборки после пересборки

| Проверка | Ожидание |
|---|---|
| `java -javaagent:x.jar -cp ... Main` | `Instrumentation agents are not supported in this VM`, старт невозможен |
| `java -agentpath:x.dll ...` / `-agentlib:x ...` / `-Xrun...` | `Agents are not supported in this VM`, старт невозможен |
| `java --patch-module=java.base=...` / `--upgrade-module-path=...` | `Module override is not supported in this VM` — подмена `PmchGuard`/`PmchStrings`/`System`-патча закрыта |
| `java -Xshare:dump ...` | `Shared archive dumping is not supported in this VM` — архив с расшифрованными классами не снять |
| `jcmd <pid> ...` / attach (`jstack`, `jmap` без `-F`) | `AttachNotSupportedException` (флаг `-XX:+DisableAttachMechanism`) |
| `jhsdb` / `jmap -F` разбор памяти | слепота: `gHotSpotVMStructs` нет (`-vm-structs`) |
| sealed/legacy клиент без агентов | работает, condy- и `PmchStrings`-строки раскрываются |
| `dumpbin /exports jvm.dll \| findstr gHotSpotVMStruct` | пусто (в ванильном JDK — 4 символа) |

## Результаты проверки (живая сборка, OpenJDK 21u, MSVC 2022, Windows x64)

| Проверка | Результат |
|---|---|
| Чистая сборка `-vm-structs`, разложенный образ | `REAL_EXIT=0`, `jvm.dll` перелинкован |
| **jarhook (per-class ключи)** на пропатченном JDK, верный `PMCH_PASS` | классы расшифрованы движком (ключ `HMAC(master, имя_класса)`), клиент отработал, `rc=0` |
| Неверный `PMCH_PASS` | `ClassFormatError: Incompatible magic value 1347240776` (= `PMCH`) |
| **sealed v3** (`PMCH_SEAL`=FILE_KEY), loader-рантайм на cp | классы расшифрованы (opaque-predicate kmix), condy-строки и `PmchStrings` раскрыты, `rc=0` |
| sealed без `PMCH_SEAL` | `Incompatible magic value` — защита держит |
| `-javaagent` / `-agentlib:jdwp` / `-agentpath` / `-Xrun` | «Agents/Instrumentation agents are not supported», VM не стартует, `rc=1` |
| `--patch-module=java.base=...` / `--upgrade-module-path=...` | «Module override is not supported», `rc=1` |
| `-Xshare:dump` | «Shared archive dumping is not supported», `rc=1` |
| `jcmd <pid> Thread.print` (цель с `-XX:+DisableAttachMechanism`) | `AttachNotSupportedException`, `rc=1` |
| `dumpbin /exports jvm.dll` на `gHotSpotVMStruct*` | 0 символов (ванильный boot JDK — 4) |
| Обычный запуск | `[pmch-guard] runtime guard active`, `rc=0` |

> Две ошибки, пойманные при проверке и исправленные: (1) в `pmchDecrypt.cpp` был обрезан
> FNV-1a offset basis (`1469598103934665603` → верное `0xCBF29CE484222325`), из-за чего
> opaque-digest не совпадал с Java и **весь sealed-путь не расшифровывался**; (2) `CondySeal`
> не исключал строки из `ConstantValue`-атрибутов полей (`static final String`), из-за чего
> класс ломался `Bad string initial value` — теперь такие строки не трогаются.
> Для sealed+condy loader-классы (`CondyStrings` и зависимости) должны быть на classpath рантайма.

## Честные оговорки

Даже с расшифровкой внутри JVM защита остаётся best-effort: в момент исполнения
байткод присутствует в памяти процесса и извлекается нативным дебагером/дампом.
Перенос крипты и ключа в машинный код (`jvm.dll`) резко поднимает планку по сравнению с
Java-classloader и снимаемым агентом, но не даёт абсолюта. Вшитые XOR-части ключа —
обфускация; стойкость обеспечивает пароль, хранящийся вне кода. Для усиления: ProGuard до
шифрования, эталонный хеш `jvm.dll`, выдача компонента ключа по сети, сборка bundled-
рантайма только с этим JDK, чтобы нельзя было подменить `java` на ванильный.
