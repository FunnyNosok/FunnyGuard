# NativeCore — вынос секретной логики в натив

Паттерн «уйти от байткода»: вся ценная логика живёт в `nativecore.dll` (машинный код,
C++/MSVC), а в байткоде остаётся только тонкий шим с объявлениями native-методов.
Декомпилятор видит `NativeCore.verifyLicense(token)` и больше ничего — ни ключа, ни
алгоритма, ни правил. Работает на **любой** JVM (не требует кастомного JDK).

Полностью нативным Minecraft-клиент сделать нельзя (клей к игре обязан быть байткодом),
но всё проприетарное выносится сюда. Клей к MC остаётся тонким и защищён вторым слоем
(шифрование + кастомный JDK из `../jdk`).

## Состав

```
nativecore/
├── java/    com/protectedclient/nativecore/NativeCore.java   тонкий шим (native-методы)
├── example/ com/protectedclient/nativecore/NativeDemo.java   пример вызова
├── native/  nativecore.cpp + CMakeLists.txt                  реализация (C++/MSVC)
└── scripts/ build.ps1, run-demo.ps1
```

## Что уже реализовано в нативе (примеры логики)

- `boolean antiDebug()` — детект отладчика (IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB).
- `long secretTransform(long)` — проприетарный алгоритм (splitmix-подобное перемешивание);
  сама формула — только в машинном коде.
- `String issueLicense(String subject)` — выпуск лицензии: AES-256-GCM шифрование субъекта
  вшитым ключом → base64-токен (вендор/сервер-сторона).
- `String verifyLicense(String token)` — проверка: расшифровка+аутентификация в нативе,
  возвращает субъект или null. Ключ и логика не покидают DLL.

Сюда же складывается твоя логика: расчёты, античит-детекты, связь с сервером, лицензии.

## Источник ключа для кастомного JDK (экспорты sgx_resolve / sgx_secret)

Кастомный `jvm.dll` (см. `../jdk`) больше не хранит секрет внутри себя — он грузит эту dll
по пути из `PMCH_CORE` и зовёт два plain-C экспорта:

- `int sgx_resolve(char* out, int cap)` — отдаёт passphrase (берёт из `PMCH_PASS`), длина в return.
- `int sgx_secret(unsigned char* out, int cap)` — отдаёт 32-байтный secret (`PART_A^PART_B^PART_C`).

Движок собирает `master = PBKDF2(passphrase || base64(secret))` — тот же ключ, что и у
упаковщика (`jarhook`). Поэтому `PART_A/B/C` здесь обязаны совпадать с `KeyManager.java`.
Запуск: `-Core <путь к nativecore.dll>` в `scripts\run-protected.ps1` (ставит `PMCH_CORE`).
Смысл выноса — закалить эту маленькую dll (VMProtect) отдельно от 14-МБ `jvm.dll`; без
VMProtect выигрыша по стойкости нет, секрет всё равно на диске.

## Сборка и запуск

```powershell
powershell -File scripts\build.ps1        # собирает nativecore.dll + Java-классы
powershell -File scripts\run-demo.ps1     # демонстрация
```

Требуется VS Build Tools (C++), CMake и полный JDK (для jni.h). Пути можно переопределить
параметрами `-Jdk` / `-Cmake`.

## Интеграция в клиент

1. Положи `nativecore.dll` рядом с клиентом.
2. В своём коде: `NativeCore.load("<путь>\\nativecore.dll");` затем зови native-методы.
   Сильнее — `NativeCore.loadVerified("<путь>\\nativecore.dll", "<sha256-hex>")`: сверяет
   SHA-256 DLL (`sha256File`) с эталоном до `System.load` и падает при подмене. Проверка
   булева (реверсер её нопит), но отсекает казуальную замену DLL.
3. Сам класс `NativeCore` и вызовы попадают в защищённый jar (шифруются как обычно),
   но даже без шифрования они бесполезны для реверса — логики в них нет.

## Честный предел

Натив тоже реверсится (IDA/Ghidra) и снимается дампом памяти в момент вызова. NativeCore
убирает атаку «декомпилировал байткод» и поднимает планку до реверса машинного кода.
Максимум достигается вместе с серверной выдачей ключей/данных (см. корневой план).
