-- ============================================================
-- RFID: unikalus kodas kiekvienam pažymėtam vienetui (pvz. ES-00042)
--  * kiekviena priskirta žyma (rfid_tags) gauna savo kodą – jį duoda SERVERIS, kartojasi niekada
--  * kodas lieka tas pats, net jei žyma perkeliama kitam daiktui ar keičiamas vieneto nr.
--  * jau priskirtos žymos gauna kodus iš eilės pagal priskyrimo laiką
--  * kodas matomas „Įrangoje“ (prie daikto – RFID vienetai) ir RFID skeneryje
-- Reikia: rfid.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create sequence if not exists public.rfid_code_seq;
alter table public.rfid_tags add column if not exists code text;

-- the ones without a code: one by one, the oldest first
do $$ declare r record; begin
  for r in select epc from public.rfid_tags where code is null order by created_at, epc loop
    update public.rfid_tags set code = 'ES-' || lpad(nextval('public.rfid_code_seq')::text, 5, '0') where epc = r.epc;
  end loop;
end $$;
create unique index if not exists rfid_tags_code on public.rfid_tags (code);

create or replace function public.rfid_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  new.epc := upper(regexp_replace(coalesce(new.epc, ''), '\s+', '', 'g'));
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
    new.code := 'ES-' || lpad(nextval('public.rfid_code_seq')::text, 5, '0');
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
    new.code := coalesce(old.code, 'ES-' || lpad(nextval('public.rfid_code_seq')::text, 5, '0'));
  end if;
  new.updated_at := now();
  return new;
end $$;

notify pgrst, 'reload schema';
