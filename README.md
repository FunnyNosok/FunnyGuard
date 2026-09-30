# FunnyGuard — защита jar (актуальная версия)

Самый сильный уровень защиты из этого проекта: **классы шифруются, а расшифровка вшита
внутрь самой JVM** (кастомный OpenJDK). Отдельный агент не нужен, на диск читаемый
байткод не пишется никогда.

Как это выглядит для атакующего: открыл защищённый jar декомпилятором → видит мусор
(`PMCH…` вместо `CAFEBABE`), классы не восстанавливаются. Расшифрованный байткод
существует только в памяти работающего процесса.

## Что нужно для защиты (две части)

1. **Упаковщик** (`src/` + `scripts/protect-jar.ps1`) — шифрует твой скомпилированный
   jar в защищённый (`jarhook`-формат: AES-256-GCM на каждый класс).
2. **Кастомный JDK** (`jdk/`) — пропатченный OpenJDK, который расшифровывает эти классы
   в движке при загрузке. Клиент запускается только на нём (или на bundled-рантайме из него).

Оба используют один ключ: `secret = (три вшитые части XOR)` + твой **пароль**, через
PBKDF2-HmacSHA256. Пароль движку передаётся при запуске через переменную `PMCH_PASS`.

## Карта папки

```
FunnyGuard/
├── README.md                 <- этот файл
├── src/                       ИНСТРУМЕНТ шифрования (билд-тайм, к юзеру не ships)
│   ├── loader/               Crypto, KeyManager, JarHookFormat, StringVault(hide),
│   │                          OpaquePredicate (Ферма+Коллатц+SHA256, load-bearing),
│   │                          SealedFormat (v3: ключ с сервера + привязка к предикату),
│   │                          HiddenLoader (defineHiddenClass + зануление буферов, без classData),
│   │                          EphemeralSession (дочерний лоадер на один вызов: анврап → define → wipe/close),
│   │                          CondyStrings (BSM-строки на FILE_KEY, кеш Cipher, ключа в пуле нет)
│   └── packer/               упаковщик (Packer: jarhook + container + seal + vault-seal + vault)
├── jdk/                       патчи кастомного JDK
│   ├── new-files/            pmchDecrypt.cpp/.hpp (HotSpot, расшифровка классов),
│   │                          PmchGuard.java (java.base, закалка),
│   │                          PmchStrings.java + PmchStrings_md.c (натив-расшифровка строк)
│   ├── patches/              диффы classFileParser.cpp и System.java
│   ├── apply.ps1             применить патчи к склонированному OpenJDK
│   └── README.md             как собрать кастомный JDK (подробно)
├── nativecore/                вынос секретной логики в натив (dll), см. его README
│   ├── java/                 тонкий Java-шим (только native-методы)
│   ├── native/               nativecore.cpp + CMake (C++/MSVC)
│   └── example/, scripts/    демо и сборка
├── license/                   серверная выдача ключа (ключ на сервере, не на диске)
│   ├── src/                  LicenseServer + LicenseClient (/license, /payload, /seal)
│   │                         boot/: MemoryLauncher/MemoryClassLoader, SealedLauncher
│   └── scripts/              build / run-server / secure-launch / run-sealed
├── scripts/
│   ├── build-packer.ps1      скомпилировать упаковщик
│   ├── protect-jar.ps1       ЗАШИФРОВАТЬ jar (legacy jarhook, пароль)  <-- обычное
│   ├── seal-jar.ps1          SEALED-билд (ключ только на сервер) <-- сильное
│   ├── run-sealed.ps1        запуск sealed-билда (ключ per-launch с сервера)
│   ├── make-vault-string.ps1 зашифровать строку для StringVault
│   └── run-protected.ps1     запустить защищённый jar на кастомном JDK
└── example/                  пример клиента (ClientMain, Greeter) для справки
```

## Быстрый старт

Предполагается, что тулчейн уже стоит (см. `jdk/README.md`): кастомный JDK собран,
а для упаковщика есть любой обычный JDK 17+.

Защитить свой jar:

```powershell
powershell -File scripts\protect-jar.ps1 -InJar C:\path\my-client.jar -OutJar C:\path\my-client-hooked.jar -Pass "мой-пароль"
```

Запустить защищённый jar на кастомном JDK:

```powershell
powershell -File scripts\run-protected.ps1 -Jar C:\path\my-client-hooked.jar -Main com.example.Main -Pass "мой-пароль"
```

Зашифровать чувствительную строку — команда печатает токен, его вставляешь в код клиента:

```powershell
powershell -File scripts\make-vault-string.ps1 -Text "https://secret-endpoint"
```

В коде клиента строка раскрывается **нативным** методом кастомного JDK (не Java):

```java
import jdk.internal.misc.PmchStrings;
...
String secret = PmchStrings.reveal(TOKEN);
```

Так как это внутренний класс JDK, клиенту нужен флаг доступа при компиляции и запуске:
`--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` (в `run-protected.ps1` уже добавлен).

Скрипты по умолчанию ссылаются на тулчейн на этой машине; путь к JDK можно переопределить
параметром `-Jdk`.

## Как собрать кастомный JDK

См. `jdk/README.md` — там полный порядок: клон OpenJDK 21u, `apply.ps1`, `configure`,
`make exploded-image`. Готовый рантайм лежит в
`...\jdk-src\build\windows-x86_64-server-release\jdk\`.

## Что защита делает и чего не делает (честно)

Делает:
- на диске нет читаемого байткода (только шифр);
- расшифровка классов и ключ — в машинном коде `jvm.dll`, реверсить дорого;
- расшифровка строк — тоже в нативе (`PmchStrings` в `java.dll`), не на Java;
- в защищённый jar попадают только классы клиента (без служебного Java-кода защиты);
- код можно раздавать **опакным контейнером** (`packer container` → `.pcc`): снаружи
  один зашифрованный блоб, ни zip-сигнатуры, ни имён классов; распаковка только в памяти
  после авторизации (`license/memory-launch`);
- закалка рантайма (`PmchGuard`): детект `-agentlib:jdwp` / `-javaagent`, отключение
  self-attach; политика `LOG` / `EXIT`.

Не делает:
- не даёт **абсолютной** защиты от дампа памяти: пока процесс жив, расшифрованный
  байткод и ключ в какой-то момент оказываются в RAM, и привилегированный атакующий
  с полным сырым дампом процесса (ProcDump / Task Manager / ring0) снимет то, что живо
  в этот миг. Полное исключение требует kernel-драйвера — сознательно не делали;
- вшитые части ключа — обфускация; стойкость даёт пароль вне кода.

### Что против дампа мы всё-таки делаем (усложняем, а не исключаем)

Не «в этот момент всё в RAM и всё» — штатные пути дампа закрыты, окно plaintext сужено:

- **Слепим штатный JVM-инструментарий дампа.** `-vm-structs` вырезает
  `gHotSpotVMStructs`/`Types`/`IntConstants`/`LongConstants` из `jvm.dll` → `jhsdb`,
  `jmap -F`, SA-сканеры метаспейса не находят точки входа (проверено `dumpbin /exports`:
  0 символов против 4 в ванильном JDK). Attach заблокирован
  (`-XX:+DisableAttachMechanism`) → `jcmd` / `jmap` / `jstack` не подключиться
  (проверено: `AttachNotSupportedException`).
- **Сужаем окно plaintext.** `EphemeralSession` / `HiddenLoader` анврапят класс,
  определяют его и **сразу зануляют** plaintext-буфер и ключ (`Arrays.fill` в `finally`);
  hidden-класс невидим для `ClassFileLoadHook` и `Class.forName`. Ключи зануляются и в
  нативе (`SecureZeroMemory`), и в Java сразу после использования.
- **Детект инструментов анализа.** `PmchGuard` ловит дебагер/агента
  (`-agentlib:jdwp` / `-javaagent` / `-agentpath`) через `VM.getRuntimeArguments()`;
  политика `EXIT` — процесс останавливается при детекте.

Граница честная: это убирает «дамп в два клика штатными тулзами» и минимизирует время
жизни ключа/plaintext, но после загрузки JVM держит представление класса в metaspace, и
полный сырой дамп RAM всё равно захватит то, что живо. Абсолюта в user-space нет —
дальше только server-side логика (см. `license/`) и kernel-драйвер.

**Серверная выдача ключа И кода (реализовано, см. `license/`):** ключ хранится на сервере
и выдаётся после авторизации (токен + HWID). Больше того — режим `memory-launch` тянет с
сервера **сам код в память** (`MemoryClassLoader`), так что на диске клиента нет даже jar.
Без сервера расшифровать/запустить нечем. Дальше по силе — держать самую ценную логику
server-side и не отдавать её на клиент вовсе.

## Sealed-режим (v3, сильнее пароля)

Проблема legacy: `PMCH_PASS` — долгоживущий пароль в скриптах/env, а boolean-проверки
патчатся. Sealed это закрывает:

- пакер генерирует случайный `FILE_KEY` (32Б) на сборку: `seal-jar.ps1` → `sealed.jar` +
  `seal.key` (48Б: key||salt). `seal.key` — **только на сервер**, клиенту не ships;
- классы шифруются `kmix = HMAC(FILE_KEY, OpaquePredicate.digest(SALT, SEED))`.
  Предикат (Ферма `powmod`, Коллатц до 5000 шагов, финал SHA-256) считается и пакером,
  и `jvm.dll` одинаково. Запачтил предикат — неверный `kmix` — GCM-тег не сошёлся —
  класс не загрузился. Проверка load-bearing, патч ломает расшифровку;
- сервер отдаёт `FILE_KEY` per-launch: `/seal` (токен + HWID + cnonce → `Ks`, ключ
  в AES-GCM, TTL 120с, привязка к HWID). `run-sealed.ps1` → `SealedLauncher` тянет ключ
  в память, fail-fast анврапит первый класс и спавнит кастомный JDK дочерним процессом,
  кладя ключ только в env дочернего (`PMCH_SEAL`). В скриптах/родителе ключа нет.
- `Packer seal` заодно шифрует строки классов в `condy` (`CondySeal`, без ASM:
  `CONSTANT_String` → `CONSTANT_Dynamic` на том же индексе, байткод и StackMapTable
  не трогаются, токен `seed||iv||ct` на `FILE_KEY` с привязкой к предикату).
  BSM `CondyStrings.bootstrap` сам подхватывает ключ из `PMCH_SEAL` дочернего процесса.
  UTF8 с plaintext затирается (только если ничто другое на него не ссылается),
  строки из `BootstrapMethods`-аргументов не трогаются.

```powershell
powershell -File scripts\seal-jar.ps1 -InJar .\client.jar -OutJar .\client-sealed.jar -KeyOut .\seal.key
powershell -File license\scripts\run-server.ps1 -Port 8077 -SealKey .\seal.key  # отдельно
$env:PMCH_JDK = "<твой собранный jdk>"; powershell -File scripts\run-sealed.ps1 `
  -Jar .\client-sealed.jar -Main com.example.Main -Token USER-001 -Secret "FUNNYGUARD-DEMO-SECRET-32bytes!!"
```

Предел прежний и честный: пока процесс жив, `FILE_KEY`/`kmix` — в RAM и снимаются
дампом. Sealed убирает офлайн-расшифровку, слив jar и реплей вне TTL, но не дамп памяти.
Проверено без пересборки JDK: 47/47 (предикат, roundtrip, tamper/wrong-key фейлятся,
per-launch выдача + HWID-bind, e2e seal реального класса с condy-строками, hidden define +
invoke + зануление, condy roundtrip/BSM/x200/wrong-key/clear/env-автоинсталл в дочернем
процессе, ephemeral child/isolation/tamper/close, integrity sha/mismatch/badhex, launcher
hash ok/mismatch/missing). Натив (`pmchDecrypt.cpp`, v3)
требует пересборки `jvm.dll`; эталонные векторы предиката для сверки натива —
`000102..0f/a0..af → digest 0badb164…8d426b39 (steps 214)`,
`fffefd..f0/01080f..6a → bcb8136d…c08c453 (steps 92)`.

## Hidden-классы и condy-строки (без пересборки JDK)

Выводы из разбора дамп-векторов, реализовано:

- `HiddenLoader.defineSealed/definePlain` — sealed-блоб анврапится и определяется через
  `Lookup.defineHiddenClass(..., NESTMATE)` без `classData` вообще: ключа в куче нет,
  plaintext-буфер зануляется сразу после define, класс невидим для `ClassFileLoadHook`
  и `Class.forName`. Ограничение hidden-модели JVM: hidden-класс обязан лежать в том же
  пакете, что и `Lookup` (иначе `IllegalArgumentException`), поэтому годится для
  entry-point'ов и однопакетных модулей, а не для всего jar целиком.
- `EphemeralSession` — sealed-модуль на один вызов в дочернем `ClassLoader`: анврап,
  `defineClass`, выполнение, `close()` с занулением блобов и копии ключа. После `close`
  и сброса ссылок лоадер с классами выгружаем. Окно видимости plaintext — время вызова.
  Классы обычные (не hidden — hidden кросс-пакетно невозможен, см. выше), поэтому CFLH
  на загрузке срабатывает: это сужение окна, а не невидимость.
- `NativeCore.loadVerified(dllPath, expectHex)` + `sha256File` — allowlist хеша DLL
  перед `System.load`: молчаливая подмена DLL ловится до загрузки. Булева проверка,
  реверсер ее нопит — отсекает казуалов и скрипты, не более.
- `SealedLauncher` — опциональный гейт `PMCH_JVM_HASH` (`run-sealed.ps1 -JvmHash`):
  перед спавном сверяет SHA-256 `jvm.dll` кастомного JDK и падает при несовпадении.
  Ловит подмену рантайма на ванильный/инструментированный.
- `CondyStrings` — BSM `bootstrap(Lookup, String, Class, String)` для `CONSTANT_Dynamic`:
  в пуле констант лежит только шифртекст-токен (`seed||iv||ct`, ключ привязан предикатом
  к доменной соли), `Cipher` кешируется в `ThreadLocal` (один `getInstance` на поток,
  а не 500), ключ ставится через `installKey`/`clearKey`. Массовая переписка
  `ldc → condy` в хост-классах требует ASM-генератора — BSM готов, рерайтер планируется.
  Токен: `Packer vault-seal --text <s> --key-hex <hex(fileKey)>`, чтение: `reveal(token)`.
- Гигиена ключей: `MemoryLauncher` зануляет скачанный payload после распаковки,
  `LicenseClient` зануляет `Ks`/плейнтекст в обоих fetch-путях, `SealedLauncher`
  зануляет secret и `FILE_KEY` после спавна.

Сознательно не реализовано: стирание байткода после JIT + pinned nmethod (нужен точный
вайп-лист scopes/dependencies при сохранении handler/oop-reloc и отключение деопта —
работа уровня форка, не патча), layout drift структур HotSpot (инвазивно, оффсеты зашиты
в шаблоны интерпретатора, C2 и GC), kernel driver (EV-сертификат, attestation, сужение
аудитории опенсорс-релиза). Дешевые оси диверсификации между билдами (соль, сиды, IV)
уже случайны на каждую сборку.

## Статус проверки (живая сборка)

Собрано и проверено на OpenJDK 21u + MSVC 2022, Windows x64:

- **Реальный клиент Minecraft 1.20.1** (7436 классов, per-class jarhook) запускается на
  кастомном JDK: LWJGL/OpenGL/OpenAL поднялись, мир сгенерировался, игрок зашёл в игру.
  Неверный/пустой `PMCH_PASS` → `Incompatible magic value 1347240776` (=`PMCH`), старта нет.
- **sealed v3** e2e: класс расшифрован по `kmix = HMAC(FILE_KEY, opaque)`, condy- и
  `PmchStrings`-строки раскрыты; без `PMCH_SEAL` — не грузится.
- **Закалка рантайма** (безусловные отказы, не зависят от feature-флагов):
  `-agentlib:jdwp` / `-javaagent` / `-agentpath` / `-Xrun` → «Agents not supported»;
  `--patch-module=` / `--upgrade-module-path=` → «Module override not supported»;
  `-Xshare:dump` → «Shared archive dumping not supported»; `jcmd`-attach →
  `AttachNotSupportedException`; `-vm-structs` → 0 символов `gHotSpotVMStruct*` в `jvm.dll`.

## Эволюция и что НЕ вошло в репозиторий

FunnyGuard — сильнейший слой (шифрование классов + расшифровка в движке кастомного JDK).
Более ранние/слабые слои в паблик-репозиторий не включены: чистый Java `ProtectedClassLoader`
(обходится своим classloader'ом или дампом) и JVMTI-агент + нативный лаунчер (агент
снимается/детектится). Из них используется только `jarhook`-формат, который здесь читает
уже сам движок JVM.
