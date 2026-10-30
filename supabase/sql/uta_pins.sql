-- ============================================================
-- UTA kortelių PIN kodai ir bendros kortelės („Mano erdvė“ → UTA)
--  * uta_cards.shared – bendra kortelė: ją (ir jos PIN) mato visi patvirtinti nariai
--  * uta_pins         – kortelės PIN kodas atskiroje lentelėje:
--                       mato tas, kam kortelė priskirta, bendrų – visi patvirtinti nariai,
--                       ir kas redaguoja „Transportą“; keičia tik kas redaguoja „Transportą“.
-- Reikia: uta.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.uta_cards add column if not exists shared boolean not null default false;

create table if not exists public.uta_pins (
  card_id    uuid primary key references public.uta_cards(id) on delete cascade,
  pin        text not null check (pin ~ '^[0-9A-Za-z]{3,12}$'),
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now()
);

-- the card is mine (given to me) or shared, and active
create or replace function public.uta_card_open(card uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.uta_cards c
                 where c.id = card and c.active
                   and (c.shared or (c.assign_kind = 'person' and c.person_id = auth.uid())))
$$;
grant execute on function public.uta_card_open(uuid) to authenticated;

alter table public.uta_pins enable row level security;
drop policy if exists "uta pins view" on public.uta_pins;
create policy "uta pins view" on public.uta_pins for select to authenticated
  using (public.can_edit('fleet') or (public.is_approved() and public.uta_card_open(card_id)));
drop policy if exists "uta pins edit" on public.uta_pins;
create policy "uta pins edit" on public.uta_pins for all to authenticated
  using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.uta_pins from anon;
grant select, insert, update, delete on public.uta_pins to authenticated;

-- members see their own card and the shared ones
drop policy if exists "uta cards own" on public.uta_cards;
create policy "uta cards own" on public.uta_cards for select to authenticated
  using (assign_kind = 'person' and person_id = auth.uid());
drop policy if exists "uta cards shared" on public.uta_cards;
create policy "uta cards shared" on public.uta_cards for select to authenticated
  using (shared and public.is_approved());

notify pgrst, 'reload schema';
