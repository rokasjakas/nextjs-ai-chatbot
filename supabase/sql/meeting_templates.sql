-- ============================================================
-- meeting_templates.sql — susitikimų šablonai (Kalendorius → + Susitikimas → Šablonas)
--  * šablone: tipas (įprastas / bendras / privatus), tema, laikas, vieta, aprašymas, nariai, el. paštai, online
--  * mato ir naudoja visi patvirtinti nariai; keisti / trinti gali jį sukūręs arba Admin. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.meeting_templates (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(name) between 1 and 80),
  data        jsonb not null default '{}'::jsonb,
  created_by  uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_name text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
alter table public.meeting_templates enable row level security;
drop policy if exists "meeting templates read" on public.meeting_templates;
create policy "meeting templates read" on public.meeting_templates for select to authenticated using (true);
drop policy if exists "meeting templates add" on public.meeting_templates;
create policy "meeting templates add" on public.meeting_templates for insert to authenticated with check (created_by = auth.uid());
drop policy if exists "meeting templates change" on public.meeting_templates;
create policy "meeting templates change" on public.meeting_templates for update to authenticated using (created_by = auth.uid() or public.is_admin()) with check (true);
drop policy if exists "meeting templates remove" on public.meeting_templates;
create policy "meeting templates remove" on public.meeting_templates for delete to authenticated using (created_by = auth.uid() or public.is_admin());
grant select, insert, update, delete on public.meeting_templates to authenticated;
notify pgrst, 'reload schema';
