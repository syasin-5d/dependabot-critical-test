# Dependabot Triage ワークフロー調査メモ

## 背景・目的

Dependabot が作成する PR について、**深刻度 Critical の脆弱性修正のみをオープンに保ち、それ以外（high/medium/low/バージョンアップのみ）は自動クローズする**ワークフローを構築・修正する。

### 対象リポジトリ

- **本番**: `visk-org/ib-kyc` — PR #294: `ci/fix-dependabot-severity-detection → develop`
- **テスト（初代）**: `syasin-5d/dependabot-critical-test` — `handlebars@4.7.6` + `fast-xml-parser@4.4.0`
- **テスト（新規・クリーン）**: `syasin-5d/dependabot-critical-test-clean` — 同上 + `minimist@1.2.5`

---

## 調査過程

### 1. 最初の実装（引き継ぎ時）

引き継ぎ時点では以下の3つの判定方法が実装されていた：

| Method | 内容 | 問題 |
|--------|------|------|
| Method 1 | `fetch-metadata` の `cvss` 出力で判定（>= 9.0 = Critical） | `cvss=0` が返ることが多い |
| Method 2 | `fetch-metadata` の `ghsa-id` を使い、Dependabot alerts API で severity 確認 | `ghsa-id` が空で返ることが多い |
| Method 3 | `ghsa-id` が空の場合、パッケージ単位で `dependabot/alerts?severity=critical&package={pkg}` を検索 | API から空レスポンスが返る |

**根底の問題**: `dependabot/fetch-metadata@v2` の `alert-lookup: true` が機能していなかった。

### 2. リトライ機構の追加

Method 3 で「PR 作成直後はアラートが API に反映されていない」可能性があるとして、**最大3回・20秒間隔のリトライ**を追加。

```bash
for attempt in 1 2 3; do
  ...
  sleep 20  # 2回目以降
  sev=$(gh api "...?severity=critical&package=${pkg}&per_page=1" ...)
  ...
done
```

**結果**: リトライしても依然として空 (`severity=''`) が返り続けた。

### 3. 核心の問題発見：GITHUB_TOKEN の権限不足

#### 実験：Actions 内から Dependabot alerts API を直接叩く

```bash
gh api "repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=5"
```

**結果**:
```json
{"message":"Resource not accessible by integration","status":"403"}
```

#### 原因

- Dependabot alerts API (`/repos/{owner}/{repo}/dependabot/alerts`) は **`repo` / `public_repo` スコープ**を必要とする
- GitHub Actions の `permissions` キーワードで指定できる権限には **`repo` スコープが存在しない**
- `security-events: read` は **Code scanning / Secret scanning** 用であり、Dependabot alerts とは別物

#### 手元 vs Actions の違い

| 環境 | トークン | API アクセス |
|------|----------|--------------|
| 手元 `gh` CLI | 個人アクセストークン（`repo` スコープ付き） | ✅ 正常にアクセス可能 |
| GitHub Actions | `GITHUB_TOKEN`（`security-events: read` のみ） | ❌ HTTP 403 |

### 4. 中間的な解決策：PAT（Personal Access Token）

`secrets.DEPENDABOT_ALERTS_TOKEN` として PAT を設定し、ワークフローで使用するように変更。

```yaml
github-token: ${{ secrets.DEPENDABOT_ALERTS_TOKEN || secrets.GITHUB_TOKEN }}
```

**検証結果**: PAT を使うと Actions 内からも Dependabot alerts API に正常にアクセスでき、**`severity='critical'` を正しく検出**できた。

**懸念**: `repo` / `public_repo` スコープを持つ PAT は強力な権限を持ち、管理・ローテーションのオーバーヘッドが大きい。

### 5. 最終的な解決策：GitHub Advisory Database API

#### 発見

GitHub Advisory Database API (`api.github.com/advisories`) は **パブリックAPIであり、認証不要**でアクセスできる。

```bash
# 認証なしでアクセス可能
curl -s https://api.github.com/advisories/GHSA-m7jm-9gc2-mpf2 | jq -r '.severity'
# → "critical"

# パッケージ名で検索も可能
curl -s "https://api.github.com/advisories?package_name=fast-xml-parser&ecosystem=npm&severity=critical&per_page=1" | jq -r '.[0].severity'
# → "critical"
```

#### Actions 内での検証

Actions 内からも同じエンドポイントにアクセスし、**認証なしで `critical` が返ることを確認**。

```
Test 1 (no auth): GET /advisories/GHSA-m7jm-9gc2-mpf2 → critical ✅
Test 2 (no auth): GET /advisories?package_name=fast-xml-parser&ecosystem=npm&severity=critical&per_page=1 → critical ✅
```

#### エコシステム名のマッピング

`fetch-metadata` の `package-ecosystem` 出力（例: `npm_and_yarn`）と Advisory Database API で必要な `ecosystem` パラメータ（例: `npm`）は異なるため、変換テーブルが必要。

| fetch-metadata 出力 | Advisory Database API |
|---------------------|----------------------|
| `npm_and_yarn` | `npm` |
| `pip` | `pip` |
| `maven` | `maven` |
| `gradle` | `gradle` |
| `bundler` | `rubygems` |
| `composer` | `composer` |
| `go_modules` | `go` |
| `cargo` | `rust` |
| `nuget` | `nuget` |

### 6. 新規リポジトリでのエンドツーエンド検証

#### セットアップ

新規リポジトリ `dependabot-critical-test-clean` を作成し、以下のファイルを配置：

- `package.json` — `handlebars@4.7.6`, `fast-xml-parser@4.4.0`, `minimist@1.2.5`
- `.github/workflows/dependabot-triage.yml` — Advisory Database API 対応版

Dependabot alerts と security updates を有効化。

#### 検証結果

| PR | パッケージ | Advisory Database 結果 | pkg_name 一致 | IS_CRITICAL | 動作 |
|----|-----------|----------------------|--------------|-------------|------|
| #1 | fast-xml-parser 5.7.0 | `critical` | `fast-xml-parser` ✅ | `1` | **オープン保持** ✅ |
| #3 | minimist 1.2.6 | `critical`（`network-ai` の誤検出） | `network-ai` ❌ | `0` | **クローズ** ✅ |

#### 発見された問題と対処

**問題 A: Advisory Database API の `severity=critical` フィルタが不完全**

`package_name=handlebars` や `package_name=minimist` のクエリでも、`network-ai` の `GHSA-qw6v-5fcf-5666` が返ってくる場合がある。

**対処**: レスポンス内の `vulnerabilities[0].package.name` が要求したパッケージ名と一致するか確認する検証を追加。

```bash
pkg_name=$(echo "$advisory" | jq -r '.[0].vulnerabilities[0].package.name // empty' 2>/dev/null) || pkg_name=""
if [ "${pkg_name}" != "${pkg}" ]; then
  echo "  Package name mismatch: expected ${pkg}, got ${pkg_name}. Skipping."
  sev=""
fi
```

**問題 B: `jq` エラーでワークフローがクラッシュ**

API レスポンスが配列ではなくエラーオブジェクトだった場合、`.[0]` で `jq` がエラー終了する。

**対処**: `jq` の stderr を `2>/dev/null` にリダイレクトし、`||` でフォールバック。

```bash
sev=$(echo "$advisory" | jq -r '.[0].severity // empty' 2>/dev/null) || sev=""
```

**問題 C: `reopened` イベントでの `github.actor` の変化**

Dependabot PR をユーザーが再オープンすると、`github.actor` がユーザー（`syasin`）になり、`if: github.actor == 'dependabot[bot]'` を満たさなくなる。

**対処**: 本番では `opened` イベントのみを使用。Dependabot PR は初回作成時にのみワークフローが実行される設計とする。

---

## 最終的なワークフロー設計

```yaml
name: Dependabot PR Triage

on:
  pull_request:
    types: [opened]

permissions:
  pull-requests: write
  contents: read

jobs:
  triage:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Fetch Dependabot metadata
        id: meta
        uses: dependabot/fetch-metadata@v2
        with:
          alert-lookup: false  # GITHUB_TOKEN では機能しない
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Triage PR based on severity
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPO: ${{ github.repository }}
          DEP_NAMES: ${{ steps.meta.outputs.dependency-names }}
          PKG_ECOSYSTEM: ${{ steps.meta.outputs.package-ecosystem }}
          UPDATE_TYPE: ${{ steps.meta.outputs.update-type }}
        run: |
          IS_CRITICAL=0
          DETECTED_BY=""

          # エコシステム名の変換
          case "${PKG_ECOSYSTEM}" in
            npm_and_yarn) ECOSYSTEM="npm" ;;
            pip)          ECOSYSTEM="pip" ;;
            maven)        ECOSYSTEM="maven" ;;
            gradle)       ECOSYSTEM="gradle" ;;
            bundler)      ECOSYSTEM="rubygems" ;;
            composer)     ECOSYSTEM="composer" ;;
            go_modules)   ECOSYSTEM="go" ;;
            cargo)        ECOSYSTEM="rust" ;;
            nuget)        ECOSYSTEM="nuget" ;;
            *)            ECOSYSTEM="${PKG_ECOSYSTEM}" ;;
          esac

          # Advisory Database API で critical アドバイザリを検索
          while IFS= read -r pkg; do
            pkg=$(echo "$pkg" | sed 's/^ *//;s/ *$//')
            [ -z "$pkg" ] && continue

            advisory=$(curl -s "https://api.github.com/advisories?package_name=${pkg}&ecosystem=${ECOSYSTEM}&severity=critical&per_page=1")
            sev=$(echo "$advisory" | jq -r '.[0].severity // empty' 2>/dev/null) || sev=""
            ghsa=$(echo "$advisory" | jq -r '.[0].ghsa_id // empty' 2>/dev/null) || ghsa=""
            cvss=$(echo "$advisory" | jq -r '.[0].cvss.score // empty' 2>/dev/null) || cvss=""
            pkg_name=$(echo "$advisory" | jq -r '.[0].vulnerabilities[0].package.name // empty' 2>/dev/null) || pkg_name=""

            # Advisory Database API の package_name フィルタが不完全な場合があるため、
            # レスポンス内の package.name が要求したパッケージ名と一致するか確認する
            if [ "${pkg_name}" != "${pkg}" ]; then
              echo "  Package name mismatch: expected ${pkg}, got ${pkg_name}. Skipping."
              sev=""
            fi

            if [ "${sev}" = "critical" ]; then
              IS_CRITICAL=1
              DETECTED_BY="Advisory Database: ${pkg} has critical advisory (${ghsa}, CVSS ${cvss})"
              break
            fi
          done < <(echo "$DEP_NAMES" | tr ',' '\n')

          if [ "$IS_CRITICAL" -eq 1 ]; then
            echo "Critical. Keeping open."
            gh pr comment "$PR_NUMBER" --repo "$REPO" --body "..."
          else
            echo "Non-critical. Closing."
            gh pr comment "$PR_NUMBER" --repo "$REPO" --body "..."
            gh pr close "$PR_NUMBER" --repo "$REPO"
          fi
```

---

## 検証結果

### テスト対象

| パッケージ | 脆弱性 | Advisory Database 結果 | pkg_name 一致 | 最終判定 |
|-----------|--------|----------------------|--------------|---------|
| `fast-xml-parser` | Critical CVE: GHSA-m7jm-9gc2-mpf2 | `critical` | `fast-xml-parser` ✅ | **Critical** |
| `minimist` | High/medium/low（Critical なし） | `critical`（`network-ai` の誤検出） | `network-ai` ❌ | **Non-critical** |

### 検証ログ（Dependabot PR 経由）

**fast-xml-parser — Critical 検出 → オープン保持**
```
DEP_NAMES=fast-xml-parser PKG_ECOSYSTEM=npm_and_yarn
Checking Advisory Database for fast-xml-parser (npm)...
  severity='critical' ghsa='GHSA-qw6v-5fcf-5666' cvss='9.9' pkg_name='fast-xml-parser'
Critical advisory found for fast-xml-parser
IS_CRITICAL=1 DETECTED_BY=Advisory Database: fast-xml-parser has critical advisory (GHSA-qw6v-5fcf-5666, CVSS 9.9)
Critical. Keeping open.
```

**minimist — 誤検出防止 → クローズ**
```
DEP_NAMES=minimist PKG_ECOSYSTEM=npm_and_yarn
Checking Advisory Database for minimist (npm)...
  severity='critical' ghsa='GHSA-qw6v-5fcf-5666' cvss='9.9' pkg_name='network-ai'
  Package name mismatch: expected minimist, got network-ai. Skipping.
IS_CRITICAL=0 DETECTED_BY=
Non-critical. Closing.
✓ Closed pull request #3
```

---

## 教訓・注意点

### 1. `security-events: read` ≠ Dependabot alerts アクセス

`permissions: security-events: read` は **Code scanning / Secret scanning** 用であり、Dependabot alerts API へのアクセス権限ではない。この点は GitHub ドキュメントでも明確に区別されている。

### 2. GitHub Advisory Database API のフィルタの不完全性

`api.github.com/advisories?package_name={pkg}&severity=critical` は、**要求したパッケージ名とは異なる advisory を返す場合がある**（`network-ai` の `GHSA-qw6v-5fcf-5666` が複数のパッケージクエリで返ってくる現象を確認）。

**必ず**レスポンス内の `vulnerabilities[].package.name` が要求したパッケージ名と一致するか検証すること。

### 3. `jq` エラーハンドリング

API レスポンスが予期しない形式（エラーオブジェクト、空配列など）の場合、`.[0]` で `jq` がエラー終了する可能性がある。`2>/dev/null` と `||` フォールバックで対処すること。

```bash
sev=$(echo "$advisory" | jq -r '.[0].severity // empty' 2>/dev/null) || sev=""
```

### 4. `fetch-metadata` の `alert-lookup` の落とし穴

`dependabot/fetch-metadata@v2` の `alert-lookup: true` は内部的に Dependabot alerts API を呼び出すため、`GITHUB_TOKEN` では機能しない。基本メタデータ（dependency-names, package-ecosystem 等）は `alert-lookup: false` でも取得可能。

### 5. `gh api` vs `curl`

`gh api` は `GITHUB_TOKEN`（`GH_TOKEN` 環境変数）を自動的に使用するため、認証不要のエンドポイントにアクセスする場合でも意図せずトークンを付与することがある。Advisory Database API へのクエリでは **`curl` を直接使用する方が確実**。

### 6. `reopened` イベントでの注意

Dependabot PR をユーザーが再オープンすると、`github.actor` がユーザーになり、`if: github.actor == 'dependabot[bot]'` を満たさなくなる。本番では `opened` イベントのみを使用する設計とする。

---

## 次のステップ

1. **本番リポジトリ (`visk-org/ib-kyc`)**: PR #294 に同じ修正を適用
2. **ドキュメント更新**: ワークフローのコメントや README に「Advisory Database API を使用している」旨を記載
3. **監視**: 本番適用後、最初の数件の Dependabot PR でワークフローの動作を確認
