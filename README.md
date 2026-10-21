# KRATOS DUMP

Приложение для Android, которое анализирует APK и нативные библиотеки `.so` (ELF; основные архитектуры ARM32 и ARM64, дополнительно x86 и x86-64) и сохраняет дампы и отчёты в выбранную папку. Анализ статический: ничего не запускается и не изменяется.

Два сценария:

- целый APK: библиотеки и файл метаданных находятся автоматически, выбор можно изменить вручную;
- отдельная библиотека `.so` с необязательным файлом метаданных.

Повреждённые, обрезанные, обфусцированные и упакованные файлы анализируются в той мере, в какой их удалось прочитать. Всё, что не удалось прочитать или что было угадано, записывается в отчёт о полноте (`reports/completeness.txt` и раздел `completeness` в `summary.json`). Итог «Успешно завершено» не выдаётся, если обязательные результаты не сохранены в выбранную папку.

## Результаты

В выбранной папке создаётся `android_dump/<имя>_<дата>_<время>/`:

```
source/       исходный APK (если включено) и список его файлов
libraries/    извлечённые библиотеки
metadata/     найденный или выбранный файл метаданных
reports/      dump.txt, completeness.txt, metadata_report.txt, analysis_log.txt
  <библиотека>/   functions.txt, methods.txt, offsets.h, strings.txt, imports.txt, exports.txt,
                  disassembly.txt, hex_dump.txt, sections.txt, segments.txt, relocations.txt, cross_references.txt
logs/         run.log, diagnostics.txt
summary.json  итог запуска
```

Какие отчёты создаются, зависит от профиля (быстрый, стандартный, подробный, максимальный) и настроек.

## Документы

- [BUILD.md](BUILD.md) — сборка, тесты, GitHub Actions, подпись.
- [DEPENDENCIES.md](DEPENDENCIES.md) — версии и лицензии зависимостей, что не подключено и почему.
- [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) — что реализовано, чем проверено, какие есть ограничения.
- [third_party/VERSIONS.md](third_party/VERSIONS.md) — история клонов и закреплённые версии.

## Быстрый старт на компьютере

```
scripts/fetch_third_party.sh        # нужен только если third_party/ пуст (в архиве проекта он заполнен)
cmake -S core -B build/core -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/core
ctest --test-dir build/core --output-on-failure
build/core/kratos_cli apk app.apk -o out/ --profile standard
```
