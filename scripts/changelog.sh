#!/usr/bin/env bash
# changelog.d/ фрагментууд ↔ CHANGELOG.md (changelog.d/README.md).
#
#   scripts/changelog.sh assemble <heading> [fragment…]
#       Фрагментуудыг (өгөөгүй бол changelog.d/*-ийн бүгдийг, нэрийн дарааллаар) CHANGELOG.md-ийн «# Changelog»-ийн
#       доор «## <heading>» гарчгаар оруулж, файлуудыг устгана. Ж: assemble "0.4.1 — 2026-10-20".
#   scripts/changelog.sh check-release <tag>
#       Release tag (v0.4.0): changelog.d-д фрагмент үлдээгүй, CHANGELOG.md-д «## v0.4.0» / «## 0.4.0» гарчиг бий
#       бөгөөд «Unreleased» биш (огноотой).
#   scripts/changelog.sh check-pr <base-sha>
#       PR: <base-sha>...HEAD нь changelog.d-ийн фрагмент эсвэл (release нэгтгэл) CHANGELOG.md-д хүрсэн.
set -euo pipefail

DIR=changelog.d
FILE=CHANGELOG.md

die() { echo "changelog: $*" >&2; exit 1; }

fragments() {
  find "$DIR" -maxdepth 1 -type f -name '*.md' ! -name README.md 2>/dev/null | LC_ALL=C sort
}

cmd=${1:-}
shift || true
case "$cmd" in
  assemble)
    heading=${1:-}
    [ -n "$heading" ] || die 'assemble "<version> — <YYYY-MM-DD>" [fragment…]'
    shift
    if [ $# -gt 0 ]; then
      files=()
      for f in "$@"; do case "$f" in */*) files+=("$f") ;; *) files+=("$DIR/$f") ;; esac; done
    else
      files=()
      while IFS= read -r f; do files+=("$f"); done < <(fragments)
    fi
    [ ${#files[@]} -gt 0 ] 2>/dev/null || die "changelog.d-д фрагмент алга"
    head -n1 "$FILE" | grep -qx '# Changelog' || die "$FILE «# Changelog»-оор эхлэх ёстой"
    tmp=$(mktemp)
    {
      echo "# Changelog"
      echo
      echo "## $heading"
      echo
      for f in "${files[@]}"; do cat "$f"; done
      echo
      tail -n +2 "$FILE" | sed '/./,$!d'
    } >"$tmp"
    mv "$tmp" "$FILE"
    rm -- "${files[@]}"
    echo "$FILE: ## $heading — ${files[*]}"
    ;;
  check-release)
    tag=${1:-}
    [ -n "$tag" ] || die "check-release <tag>"
    ver=${tag#v}
    left=$(fragments)
    [ -z "$left" ] || die "release $tag: нэгтгээгүй фрагмент — $(echo "$left" | tr '\n' ' ')(scripts/changelog.sh assemble)"
    esc=$(printf '%s' "$ver" | sed 's/\./\\./g')
    line=$(grep -E "^## v?$esc( |\$)" "$FILE" | head -n1 || true)
    [ -n "$line" ] || die "release $tag: $FILE-д «## $tag» гарчиг алга"
    if echo "$line" | grep -qi 'unreleased'; then die "release $tag: гарчиг «Unreleased» хэвээр — огноо тавь"; fi
    echo "changelog: $tag ✔ ($line)"
    ;;
  check-pr)
    base=${1:-}
    [ -n "$base" ] || die "check-pr <base-sha>"
    if git diff --name-only "$base...HEAD" | grep -E "^($FILE|$DIR/.+\.md)\$" | grep -vqx "$DIR/README.md"; then
      echo "changelog: фрагмент ✔"
    else
      die "PR-д $DIR/<YYYY-MM-DD>-<сэдэв>.md фрагмент алга ($DIR/README.md)"
    fi
    ;;
  *) die "assemble | check-release | check-pr" ;;
esac
