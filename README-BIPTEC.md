# BIPTEC FreeIPA downstream releases

Этот файл обязателен для поддерживаемых веток `biptec/<upstream-version>`.
Он описывает, как BIPTEC хранит, переносит, собирает, тестирует и выпускает собственный FreeIPA.

## 1. Модель репозитория

BIPTEC FreeIPA является постоянным downstream fork. Upstream contribution не является частью release-процесса.

- `master` должен оставаться максимально близким к upstream.
- `feat/*` хранит историю разработки и экспериментов.
- `biptec/<version>` — поддерживаемая release-ветка, основанная на конкретном upstream release tag.
- `<version>-<release>` — immutable production source tag в нашем fork.
- Production никогда не устанавливается из произвольного branch HEAD.

Для 4.13.3 базой является upstream `release-4-13-3`.
Release-ветка содержит девять логических source patches: пять исходных BIPTEC patches, перенесённых с 4.13.2, и четыре исправления, найденных при 4.13.3 lab acceptance.

## 2. Что считается релизом

Source tag сам по себе не является готовым BIPTEC release.
Релиз считается готовым только после успешной автоматической RPM-сборки для целевой Fedora.
GitHub Release для production tag должен содержать готовый DNF repository bundle, SRPM, patch stack,
`SHA256SUMS`, `RPM-MANIFEST.txt` и `BUILD-METADATA.txt`.
GitHub Actions workflow `.github/workflows/biptec-release.yml` запускается:

- на каждом push в `biptec/**` — CI build без публикации GitHub Release;
- при push production tag, начинающегося с цифры (`<version>-<release>`), — повторная сборка и публикация GitHub Release;
- вручную через `workflow_dispatch`, когда workflow доступен в default branch.

Tag обязан совпадать с `BIPTEC-RELEASE`:

```text
${PACKAGE_VERSION}-${RELEASE_REVISION}
```

Например:

```text
4.13.3-1
```

## 3. Machine-readable release metadata

`BIPTEC-RELEASE` фиксирует upstream tag/commit, Fedora dist-git commit, target Fedora,
номер release revision и границы source patch stack.

Изменять source code после `PATCH_HEAD` нельзя. Если код изменился, он должен стать новым логическим
patch commit, после чего необходимо обновить `PATCH_HEAD`, `PATCH_COUNT` и после source-review зафиксировать
`VALIDATED_TREE`. Production tag всё равно запрещён до полного lab acceptance.
## 4. Patch stack

Patch files не редактируются вручную и не являются источником истины. Источник истины — Git commits
между `PATCH_BASE` и `PATCH_HEAD`.

Проверка source release:

```bash
biptec/release/verify-source.sh
```

Экспорт RPM-compatible patches:

```bash
biptec/release/export-patches.sh /tmp/biptec-patches
```

Для текущей 4.13.3 должны получиться девять файлов с номерами `9001`–`9009`.
High patch numbers выбраны намеренно: Fedora downstream patches применяются первыми, BIPTEC patches — после них.

## 5. Fedora packaging

BIPTEC RPM строится не из upstream `freeipa.spec.in`, а поверх зафиксированного Fedora dist-git.
Это принципиально: production package должен сохранять Fedora packaging, зависимости и build semantics,
на которых выполнялись интеграционные тесты.

`prepare-distgit.sh`:

1. проверяет точный Fedora dist-git commit;
2. добавляет экспортированные BIPTEC patches;
3. меняет только RPM `Release` на `N.M%{?dist}`;
4. оставляет upstream signed source tarball и Fedora spec semantics.
Текущая схема версии RPM:

```text
FreeIPA 4.13.3 + Fedora release 1.1 + release revision 1
=> 4.13.3-1.1.1.fc44
```

Сборка локально на Fedora 44 выполняется тем же script, что и CI:

```bash
sudo dnf install git rpm-build rpmdevtools dnf-plugins-core fedpkg createrepo_c python3
sudo biptec/release/build-fedora-rpms.sh
```

Build script сам загружает Fedora source archive из dist-git lookaside, устанавливает BuildRequires,
применяет patch stack, строит binary RPM/SRPM, создаёт `repodata/` и release bundle.

## 6. Быстрая установка из готового release

Production host не должен компилировать FreeIPA. Основной release asset — архив вида:

```text
freeipa-4.13.3-1.1.1.fc44-x86_64-repo.tar.gz
```

После распаковки каталог `repo/` является обычным DNF repository с RPM и `repodata/`.
Его можно разместить на внутреннем HTTPS repository server либо использовать через `file://` для lab.
Перед использованием обязательно проверить `SHA256SUMS` и `BUILD-METADATA.txt`.

RPM signing в workflow намеренно не использует встроенный private key. Если BIPTEC вводит собственный
RPM/repository signing key, private material должен храниться вне Git и подключаться через защищённый
release environment или отдельный signing stage.
## 7. Переход на новую upstream FreeIPA

При выходе следующей версии не merge-ить новый upstream в текущую `biptec/4.13.3`.
Создать новую ветку от нового чистого upstream release tag:

```bash
git fetch upstream --tags
git switch -c biptec/4.13.4 release-4-13-4^{}
```

Затем перенести пять логических BIPTEC commits через cherry-pick/rebase, разрешая конфликты отдельно
по каждому функциональному блоку. После переноса обязательно использовать `git range-diff`, чтобы
сравнить старую и новую patch series и обнаружить случайные семантические изменения.

После успешного переноса обновить `BIPTEC-RELEASE`: upstream commit/tag, Fedora branch/dist-git commit,
package version, patch head/count и после source-review — `VALIDATED_TREE`. Production tag создаётся только после полного lab acceptance.

Не переносить patch, если новая upstream версия уже реализует эквивалентное поведение: вместо этого
удалить или уменьшить соответствующий downstream commit и повторить весь acceptance suite.

## 8. Обязательная upgrade rehearsal

Fresh install новой версии недостаточен. Перед production release CI/lab обязан взять состояние,
созданное предыдущим BIPTEC release, и обновить его на новый candidate.
Минимальный rehearsal:

```text
old BIPTEC DC1 + old BIPTEC DC2
        ↓
upgrade DC2 to candidate
        ↓
replication / DNS / Kerberos / HTTP / CA / AD Trust / listeners / reboot
        ↓
upgrade DC1 to candidate
        ↓
тот же acceptance + cold reboot обоих DC
        ↓
endpoint enrollment/authentication/failover
        ↓
failed replica promotion + transactional rollback
```

Проверять нужно не только `ipa.service`, но и отсутствие service exposure на management identity,
отдельные Directory/DNS identities, `DNS/nsX` keytab, topology owner `dcX`, CLDAP/Samba identities,
replication agreements, `ipa-certupdate`, `ipa-server-upgrade` и холодную загрузку.

## 9. Production rollout

После успешного rehearsal и готового binary GitHub Release:

1. зафиксировать backup/snapshot policy и health baseline;
2. обновить DC2 первым;
3. полностью проверить DC2 и mixed-version replication;
4. только затем обновить DC1/Prime;
5. проверить оба DC и endpoint failover;
6. не держать mixed-version cluster дольше необходимого.

Downgrade RPM не считается rollback-механизмом. Изменения LDAP schema/shared state могут уже быть
реплицированы. Основная защита — заранее проверенный upgrade path и recovery procedure.
## 10. Что не входит в FreeIPA downstream

NTP/chrony, NetworkManager VLAN configuration, firewall policy и общий host provisioning являются
отдельным infrastructure layer. FreeIPA можно устанавливать с `-N`, а chrony настраивать независимо.
Это уменьшает patch surface и делает FreeIPA upgrades независимыми от NTP service lifecycle.

## 11. Release checklist

Перед production tag должны быть выполнены все пункты:

- `biptec/release/verify-source.sh` проходит;
- source tree соответствует прошедшему lab acceptance;
- Fedora dist-git commit зафиксирован;
- branch CI RPM build зелёный;
- upgrade rehearsal old → new зелёный;
- fresh DC1/DC2 install/promotion зелёный;
- AD Trust и endpoint tests зелёные;
- failed promotion rollback зелёный;
- binary repository bundle проверен установкой в clean Fedora VM;
- `BIPTEC-RELEASE` содержит финальный `RELEASE_REVISION`.

После этого создаётся annotated tag и отправляется в origin:

```bash
git tag -a 4.13.3-1 -m 'BIPTEC FreeIPA 4.13.3 release 1'
git push origin 4.13.3-1
```

Tag запускает тот же build pipeline заново. GitHub Release создаётся только если эта tagged build
успешно завершилась. Название GitHub Release должно в точности совпадать с именем tag (например,
`4.13.3-1`). Не прикреплять вручную RPM из более раннего branch build к production release.
