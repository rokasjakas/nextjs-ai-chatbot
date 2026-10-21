# EventSolutions App – notes for Claude

- The app is one file: `site/index.html` (Cloudflare Pages deploys it from branch `claude/wizardly-cori-j2tuff`).
- **Icons: always Material Symbols (Google) · Outlined · Fill (Apache 2.0)** – package `@material-symbols/svg-400`,
  folder `outlined/`, files `*-fill.svg` (viewBox `0 -960 960 960`). Add a new icon to `SL` as
  `<path fill="currentColor" stroke="none" transform="matrix(.025 0 0 .025 0 24)" d="…"/>` and draw it with `slIcon(key)`.
  Never use emoji or hand-drawn SVG as an icon in the interface; an emoji typed in UI text must have an `EI_MAP` entry
  (it is swapped for the Material icon at runtime).
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
