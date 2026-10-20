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
