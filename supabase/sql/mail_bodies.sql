-- ============================================================
-- El. paštas: laiškai atsidaro iš karto
--  * mail_bodies – naujausių laiškų turinys (tekstas, priedų sąrašas);
--    „mail“ funkcija jį parsisiunčia fone (kartu su laiškų sąrašu, kas minutę),
--    o programa laišką atidaro iš čia – nelaukdama pašto serverio.
--    Laikoma tik ~60 naujausių kiekviename aplanke; senesni skaitomi kaip anksčiau.
--  * kiekvienas mato TIK SAVO laiškus; rašo tik serverio funkcija
-- Reikia: „mail“ funkcija v12 (supabase functions deploy mail).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.mail_bodies (
  user_id    uuid not null references auth.users(id) on delete cascade,
  folder     text not null,
  uid        bigint not null,
  data       jsonb not null,
  fetched_at timestamptz not null default now(),
  primary key (user_id, folder, uid)
);

alter table public.mail_bodies enable row level security;
drop policy if exists "own mail bodies" on public.mail_bodies;
create policy "own mail bodies" on public.mail_bodies for select to authenticated using (user_id = auth.uid());
revoke all on public.mail_bodies from anon;
revoke insert, update, delete on public.mail_bodies from authenticated;
grant select on public.mail_bodies to authenticated;

-- atsijungus nuo pašto – ir laiškų turinys ištrinamas
create or replace function public.mail_bodies_cleanup() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  delete from public.mail_bodies where user_id = old.user_id;
  return old;
end $$;
drop trigger if exists mail_bodies_cleanup on public.mail_accounts;
create trigger mail_bodies_cleanup after delete on public.mail_accounts
  for each row execute function public.mail_bodies_cleanup();
