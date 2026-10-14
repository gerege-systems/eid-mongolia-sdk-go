# changelog.d — нэг өөрчлөлт, нэг файл

`CHANGELOG.md`-г салбар/PR дотор засахгүй. Өөрчлөлт бүр `changelog.d/<YYYY-MM-DD>-<сэдэв>.md` файлд: юу · яагаад ·
хаана · хэрхэн шалгасан. CI (`changelog` job) PR бүрд фрагмент (эсвэл release нэгтгэл) шаардана.

Release (tag-ийн өмнөх commit): `scripts/changelog.sh assemble "<version> — <YYYY-MM-DD>"` — фрагментуудыг
`CHANGELOG.md`-ийн шинэ гарчгийн доор оруулж файлуудыг устгана (гарчиг аль хэдийн байвал фрагментыг гараар тэр хэсэгт
зөөж «Unreleased»-ийг огноогоор солино). `v*` tag push хийхэд `.github/workflows/release.yml`
(`scripts/changelog.sh check-release`) фрагмент үлдсэн, гарчиг алга эсвэл «Unreleased» хэвээр бол улаан болно.
