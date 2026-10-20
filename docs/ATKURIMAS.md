# Atsarginės kopijos ir atkūrimas

Kas naktį GitHub darbas **„Atsarginės kopijos“** (`.github/workflows/backup.yml`) nukopijuoja:

| Kas | Kur | Kaip ilgai |
|---|---|---|
| Duomenų bazė (visos programos lentelės, narių prisijungimai, failų sąrašai) | hostinge `BACKUP_DIR/duomenu-baze/db-METAI-MĖN-DIENA.tgz.enc` ir GitHub (Actions → Artifacts) | 30 d. hostinge, 7 d. GitHub |
| Supabase Storage failai (kvitai, sąskaitos, darbų nuotraukos, laiškai) | hostinge `BACKUP_DIR/…` (užšifruoti, pavadinimai irgi) | visi, papildomai tik nauji |
| Cloudflare R2 failai | hostinge `BACKUP_DIR/…` (užšifruoti) | visi, papildomai tik nauji |

Viskas užšifruota slaptažodžiu **BACKUP_PASSWORD**. Be jo kopijų atkurti neįmanoma – laikykite jį atskirai (pvz. slaptažodžių tvarkyklėje ar užrašytą saugioje vietoje).
Paskutinės kopijos būsena matoma programoje: **Sistema → Nustatymai → Atsarginės kopijos**. Nepavykus, GitHub atsiunčia laišką repozitorijos savininkui.

## Duomenų bazės atkūrimas

Reikia: `openssl`, `tar`, PostgreSQL įrankių (`pg_restore`, 17 versija) ir naujos duomenų bazės (naujas Supabase projektas arba savas Supabase serveris).

```bash
# 1. iššifruoti ir išskleisti
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in db-2026-10-21.tgz.enc -pass pass:'BACKUP_PASSWORD' | tar -xz
# → db/public.dump (programos duomenys), db/auth-storage.dump (prisijungimai ir failų sąrašai)

# 2. naujame Supabase projekte: Supabase → Connect → Session pooler eilutė
export DB='postgresql://postgres.…:SLAPTAŽODIS@…pooler.supabase.com:5432/postgres'

# 3. programos lentelės, duomenys ir jų teisės (GRANT – būtina: nuo 2026-10-30 Supabase naujoms lentelėms jų pats neduoda)
pg_restore --no-owner -d "$DB" db/public.dump
# senesnėse kopijose (be teisių) – po to paleisti supabase/sql/grants_restore.sql

# 4. narių prisijungimai ir failų sąrašai (tik duomenys)
pg_restore --no-owner --no-privileges --data-only --disable-triggers -d "$DB" db/auth-storage.dump
```

Po to: `supabase/sql/atnaujinimas.sql` funkcijos ir taisyklės jau būna atkurtos su `public` schema; serverio funkcijas įdiegti iš naujo (GitHub → Actions → „Supabase funkcijos“ → Run, „Įdiegti visas“), raktus suvesti Supabase → Edge Functions → Secrets (sąrašas – perdavimo dokumente), programoje (`site/index.html`) pakeisti `SUPABASE_URL` ir `SUPABASE_KEY` į naujo projekto.

## Failų atkūrimas

Reikia programos [rclone](https://rclone.org). Nustatymai (tie patys kaip kopijavimo):

```bash
export RCLONE_CONFIG_DEST_TYPE=sftp   # arba ftp
export RCLONE_CONFIG_DEST_HOST=… RCLONE_CONFIG_DEST_USER=…
export RCLONE_CONFIG_DEST_PASS="$(rclone obscure 'HOSTINGO_SLAPTAŽODIS')"
export RCLONE_CONFIG_SAFE_TYPE=crypt RCLONE_CONFIG_SAFE_REMOTE="dest:atsargines-kopijos"
export RCLONE_CONFIG_SAFE_PASSWORD="$(rclone obscure 'BACKUP_PASSWORD')"

rclone ls safe:failai                       # ką turime (pavadinimai jau iššifruoti)
rclone copy safe:failai/supabase ./failai   # Supabase Storage failai: aplankas = saugykla (bucket)
rclone copy safe:failai/r2 ./r2             # Cloudflare R2 failai
```

Supabase failus atgal įkelti: naujame projekte sukurti tokio paties pavadinimo saugyklas (bucket) ir įkelti aplankų turinį (Supabase → Storage arba `rclone` su Supabase S3 prieiga). R2 failus – į naują R2 saugyklą (`rclone copy ./r2 r2:SAUGYKLA`).
