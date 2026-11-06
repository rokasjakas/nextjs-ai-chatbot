-- ============================================================
-- Sutikimai dėl asmens duomenų tvarkymo (Privatumo politika – site/privatumas.html)
--  * consents – kas, kada, su kuria politikos versija sutiko ir kur (registracija / programa / sąskaitų portalas)
--  * įrašyti gali tik pats narys savo vardu (sąskaitų portalo – serverio funkcija freelance-portal)
--  * skaityti visus gali tik Admin+ ir Super Admin; narys mato tik savo įrašus (kad programa žinotų, ar jau sutiko)
--  * įrašai nekeičiami ir netrinami (įrodymas)
-- Paleidžiama per „SQL paleidimas“. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.consents (
  id          bigserial primary key,
  user_id     uuid references auth.users(id) on delete set null,
  email       text not null default '',
  name        text not null default '',
  doc_version text not null,
  source      text not null default 'app' check (source in ('register','app','saskaitos')),
  user_agent  text,
  accepted_at timestamptz not null default now()
);
create unique index if not exists consents_user_ver on public.consents (user_id, doc_version) where user_id is not null;
create unique index if not exists consents_email_ver on public.consents (lower(email), doc_version, source) where user_id is null;
create index if not exists consents_time on public.consents (accepted_at desc);

-- Admin+ (role admin, level plus) and Super Admin
create or replace function public.consent_viewer() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select level = 'super' or (role = 'admin' and level = 'plus') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.consent_viewer() to authenticated;

alter table public.consents enable row level security;
drop policy if exists "consent own insert" on public.consents;
create policy "consent own insert" on public.consents for insert to authenticated with check (user_id = auth.uid());
drop policy if exists "consent read" on public.consents;
create policy "consent read" on public.consents for select to authenticated using (user_id = auth.uid() or public.consent_viewer());
grant select, insert on public.consents to authenticated;
grant usage, select on sequence public.consents_id_seq to authenticated;
grant all on public.consents to service_role;
grant usage, select on sequence public.consents_id_seq to service_role;

notify pgrst, 'reload schema';
select 'consents' as k, count(*)::text as v from public.consents
union all select 'nariai (patvirtinti)', count(*)::text from public.profiles where role not in ('pending','blocked');
