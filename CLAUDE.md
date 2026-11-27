# EventSolutions App – notes for Claude

- The app is one file: `site/index.html` (Cloudflare Pages deploys it from branch `claude/wizardly-cori-j2tuff`).
- **Icons: always Material Symbols (Google) · Outlined · Fill (Apache 2.0)** – package `@material-symbols/svg-400`,
  folder `outlined/`, files `*-fill.svg` (viewBox `0 -960 960 960`). Add a new icon to `SL` as
  `<path fill="currentColor" stroke="none" transform="matrix(.025 0 0 .025 0 24)" d="…"/>` and draw it with `slIcon(key)`.
  Never use emoji or hand-drawn SVG as an icon in the interface; an emoji typed in UI text must have an `EI_MAP` entry
  (it is swapped for the Material icon at runtime).
  A button holding only such a symbol gets `ei-solo` (icon centred); a button with only the letter „ד gets the close icon (`eiScan`).
- **Sistema** (Super Admin page, `renderSystemTab`): the map comes from `site/sys-map.json` – rebuild it at every release with
  `python3 site-tools/sys_build.py site/index.html supabase/functions site/sys-map.json`. Errors are collected by `SYSLOG`
  (table `app_errors`, `supabase/sql/app_errors.sql`); explanations live in `sysExplain`.
- Menu names / icons / order / turned-off pages come from `app_config` key `nav` (`CFG`, `cfgApply`, `supabase/sql/app_config.sql`),
  edited in Sistema → Nustatymai; never hard-code a rename that the Super Admin could set there. Status names / colours and
  free lists (`SYS_LISTS`, key `lists`) are overlaid on the code constants by `listsApply` – a new list goes into `SYS_LISTS`.
- **Konstruktorius** (Sistema → Puslapiai): Super Admin's own pages in `custom_pages` (`supabase/sql/custom_pages.sql`), menu keys
  `cp_<id>`; runtime `cpMount`/`cpDo`, editor `cpEdit` (state `CPE`). „Program functions“ are replayed clicks (`cpPlay`) on button
  ids – the catalog is `pages[k].ui` in `site/sys-map.json`; keep useful buttons' `id`s stable so built pages keep working.
  Model is Figma's: page frames = sub-pages (`subnav` element lists them), popup frames = overlays with `f.ov` (pos incl. `under`,
  outside, dim); every element / frame has `ia` interactions {on → do → anim, dir, ease, ms} run by `cpBind`/`cpRun`/`cpTrans`
  (smart animate matches layers by `k`, kept on frame duplicate / paste to another frame); old single `act` is read by `cpIa`.
  Design uses theme tokens `var:<name>` (`CP_TOK`), text styles `CP_TS`, button kinds, and the program's components `CP_COMPS`
  (`cpk-*` CSS); templates `CP_TPL`; overview `cpEdMap`; help `cpEdHelp`. `cpDo`/`cpPopup` keep their old signatures (used by „Redaguoti puslapius“).
- Super Admin account safety: it works only in a browser where its password was typed (`superTrusted`, localStorage `esSupTrust`,
  else `superLock` full-screen); from another level („Kaip: Tech“) going back / switching asks the password (`superAskPass`, 15 min
  `superFresh`). The header shield button and „Atnaujinimai“ show only in the Super Admin level. A release that must reach open windows
  at once sets `FORCE_FOR` in `site/sw.js` to its own CACHE name (windows reload right after the worker activates – never inside the activate
  waitUntil: that deadlocks, v619 left phones on a black screen; later releases are not forced).
- Sistema → Įjungti / išjungti (`sysOffHtml`, `offPick`): pages = nav off; buttons with an id (top bar, left menu extras, right panel,
  a page's catalog buttons) = `app_config` key `off` {ids:{selector:{t,a}}, apps} hidden by one style sheet (`offApply`, scoped by
  `body[data-tab]`); anything else picked on the page = the page editor's `h` rule. The Super Admin (Super Admin level) sees them dimmed.
- Existing pages are edited in place (Super Admin → „Redaguoti puslapius“ or Sistema → Puslapiai → Esami programos puslapiai):
  rules in `STATE.uiLayout.ed[scope]` keyed by the element's name (`edTextKey`) – t name, i icon, o order, f fold, h hidden,
  s look, a click (`edRunAct`), n inserted elements (`edIns`). Renaming a button's text in code breaks its rules – keep names.
- Nightly backups: `.github/workflows/backup.yml` (DB pg_dump + Storage + R2, encrypted with `BACKUP_PASSWORD`, to the hosting via
  rclone SFTP/FTP and 7 days as a GitHub artifact); result in `app_config` key `backup`; restore steps in `docs/ATKURIMAS.md`.
- From 2026-10-30 Supabase no longer grants Data API access to NEW public tables: every new `create table` in `supabase/sql/*.sql`
  must carry its own `grant … to authenticated` (and `to service_role` when a server function or the backup touches it; `anon`
  only when the table is read before sign-in). Backups keep the grants (`pg_dump` without `--no-privileges`).
- Įrankiai (`tools` tab, warehouse group) → LED skaičiuoklė (`ledCalc`, `ledPorts`): 650 000 px per NovaStar Gigabit port at 60 Hz / 8 bit,
  scaled by 60/fps and halved at 10/12 bit. Devices/cabinets defaults `LED_DEVICES` / `LED_PANELS`; Super Admin overrides in
  `app_config` key `led_db` (`check:true` = figure to verify against the datasheet).
  Port load = rectangle around the port's cabinets for every device (SmartLCT shows 5 diagonal cabinets as 5×5), only UNICO Free Topology (`free:true`) counts the cabinets;
  low latency cap = (1 − Y/H) × 650 000; Ethernet backup Split / Sequential halves usable ports; 3D side-by-side halves capacity.
  Įrankiai is a launcher of tool apps (`TOOL_APPS`, `toolOpen`); the LED tool is a SmartLCT-like editor (`LP` project in localStorage
  `ledProj`, `lpDraw`, `lpWire`, `lpPattern`, `lpTotals`): free pixel canvas, several cabinet types, ports wired by hand or by pattern.
  Only verified processors are built in (`LED_DEVICES`: h16, vx1000, vx1000pro, mctrl4k) and no cabinets (`LED_PANELS = []`): users add
  their own (`ledPanelForm`, `ledDevForm`, a PDF read by `ledDevPdf` → `ledParseSpec`), saved for everyone (`led_db`, Super Admin) or in
  this browser (`ledMyPanels` / `ledMyDevices`); a project keeps a copy of its cabinets in `LP.customs`. Wiring by hand never jumps to the
  next port – the overload shows red (`lpOverFrom`, `lpHud`); Esc or the same port again ends drawing (`lpWireEnd`); patterns do move on. Quick calculation (m² or W×H → ports): `ledQuickCalc`.
- Paieška (`gsSearch`, Ctrl K): people (members, Žmonės contacts, names only in events' crew) open `dzPerson(name)`, items open `dzItem(id)` –
  the dossier (events by crew / manager / driver, calls, gear issues, item works; item free on a day via `dzItemFree` = `grsCalc` logic).
- Gidas (tab `guide`, `renderGuideTab`): hand-written articles in `GUIDE` (group, tab, sections, Q&A, related); buttons and shared-data
  pages come from `site/sys-map.json`; „Klausti AI“ = ai-chat with the best articles as context. The guide shows NO changelog / updates
  and NOTHING of the Super Admin or the Admin page (no Sistema / Admin articles, no Super Admin text, buttons filtered by `GD_SUP_UI`;
  `gdCan` = `canView` minus `GD_NO_TAB`). Every link out of the guide, the search (`gsSearch`: pages by `canView`, header functions by
  `gsBtnOk`) and the dossier cards re-checks the level – a level never reaches a page it may not see.
  **Every release that adds or changes a feature updates its `GUIDE` article / Q&A in the same release** (the user asked for it);
  run `python3 site-tools/guide_check.py site/index.html` at every release – it fails when a menu page has no article.
- The El. paštas page was REMOVED (v632, the user's wish): tab `mail` is in `HIDDEN_TABS`, no rail button, no mailbox sync jobs
  (`supabase/sql/mail_off.sql`: only cron `invoice-inbox` → mail function `{action:"invoice_inbox"}`), mail-in drops letters
  (`MAIL_IN_ON`≠1). What stays: the invoice mailbox (saskaitos@ → Sąskaitos) and SENDING from the member's own mailbox
  (event letter `lm*`, invoices `invSendModal`) – connected in the small `mailSendSetup()` window. Don't bring the mailbox back unasked.
- Running SQL on the live database: write `supabase/sql/<name>.sql`, put `<name>.sql` (+ a `# timestamp` line) into
  `supabase/sql-run.txt` and push – `.github/workflows/sql-run.yml` runs it with the `SUPABASE_DB_URL` secret (session pooler,
  IPv4); the result comes back as a check-run notice (read via `check-runs/<job id>/annotations`). Never send mass deletes
  this way without the user's explicit OK; `supabase/sql/db_check.sql` is a read-only health check (cron jobs, top writers, DB size).
