# License — серверная выдача ключа

Ключ расшифровки **не хранится на клиенте**. Он живёт на сервере и выдаётся только после
авторизации (токен + привязка к HWID). На диске у пользователя — зашифрованный jar без
ключа: **без сервера расшифровать нечем**. Это закрывает атаки «утащил файл с диска» и
«слил лаунчер».

## Как работает

```
[клиент] ── token + hwid + client-nonce ──▶ [сервер]
                                             проверяет токен активен
                                             привязывает/сверяет hwid
[клиент] ◀── server-nonce + AES-GCM(Ks, ключ) ──
   Ks = HMAC-SHA256(secret, client-nonce+server-nonce)
   клиент знает secret → расшифровывает ключ в память
   → PMCH_PASS → запуск на кастомном JDK
```

- **secret** (лицензия пользователя) — выдаётся вендором, у клиента; доказывает право.
- **Ключ выдачи** (`PMCH_PASS`) — только на сервере, на диск клиента не попадает.
- **HWID-привязка** — токен привязывается к машине при первом использовании; с другой
  машины сервер отвечает `403 hwid mismatch`. Вендор может отозвать токен на сервере.
- **Ключ на проводе** зашифрован Ks (поверх TLS в проде) — знать secret обязательно.

## Состав

```
license/
├── src/  com/protectedclient/license/LicenseServer.java   HTTP-сервер: /license (ключ) + /payload (код) + /seal (per-launch FILE_KEY)
│                                     LicenseClient.java   хендшейк, HWID, расшифровка ключа (+fetchSealedKey с TTL/HWID-проверкой)
│         com/protectedclient/boot/  MemoryLauncher.java  качает код с сервера в память и запускает
│                                     MemoryClassLoader.java  in-memory загрузчик (defineClass из памяти)
│                                     SealedLauncher.java  per-launch FILE_KEY → fail-fast unwrap → дочерний JDK с PMCH_SEAL
└── scripts/ build.ps1, run-server.ps1, secure-launch.ps1, memory-launch.ps1
```

## Два режима запуска

- **secure-launch.ps1** — jar лежит на диске (зашифрован), ключ приходит с сервера.
- **memory-launch.ps1** — **на диске нет даже jar**: код (`/payload`) и ключ (`/license`)
  тянутся с сервера в память, классы определяются `MemoryClassLoader` и расшифровываются
  движком кастомного JDK. Проверено: `pulled ... bytes into memory`, класс загружен
  `MemoryClassLoader`, клиент отработал; неверный токен → `payload denied: 403`.
  Сервер запускать с путём к payload: `run-server.ps1` → `LicenseServer <port> <payload.jar>`.
- **sealed (v3, см. корневой README)** — `Packer seal` → `sealed.jar` + `seal.key` на сервер;
  `run-server.ps1 -SealKey seal.key` поднимает `/seal` (per-launch `FILE_KEY`, TTL 120с,
  HWID-bind); запуск через корневой `scripts\run-sealed.ps1` (`SealedLauncher`).
  Важно: для condy-строк loader-рантайм (`CondyStrings` и зависимости из `src/loader`)
  должен быть на classpath запускаемого процесса — BSM `CondyStrings.bootstrap`
  вызывается при первом обращении к запечатанной строке и берёт ключ из `PMCH_SEAL`.

## Демонстрация

```powershell
powershell -File scripts\build.ps1
powershell -File scripts\run-server.ps1                 # в отдельном окне; сеет USER-001
powershell -File scripts\secure-launch.ps1 `
  -Jar <протектед.jar> -Main <главный.класс> `
  -Token USER-001 -Secret "FUNNYGUARD-DEMO-SECRET-32bytes!!"
```

Проверено:
- валидный токен+секрет+hwid → ключ в память → клиент запустился;
- неверный секрет → `gcm decrypt failed` (ключ не расшифровать);
- чужой hwid → `403 hwid mismatch`.

## Честные оговорки и продовые улучшения

- Демо-сервер хранит пользователей в памяти и сеет одного (`USER-001`). В проде — БД,
  выпуск токенов, отзыв, срок действия.
- Обязателен **HTTPS + pinning** сертификата (иначе владелец машины снимет поток MITM).
- Клиентский хендшейк стоит вынести в **натив** (`../nativecore`): тогда secret, протокол
  и HWID-логика не в байткоде. Сейчас для демо клиент на Java.
- Сильнее ключа: **отдавать с сервера сам код** (классы в память, не на диск) и держать
  ценную логику server-side.
- Предел прежний: у легального авторизованного пользователя ключ и код в момент работы —
  в RAM, и снимаются дампом. Сервер убирает офлайн-атаки, но не дамп памяти.
