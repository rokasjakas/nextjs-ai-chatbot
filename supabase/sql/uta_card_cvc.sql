-- ============================================================
-- UTA kortelės kodas – skaičiai kortelės gale po „CVC:“ – „Kuro kortelė“ renginio laiške: vairuotojas
-- juos nurašo, funkcija „uta-pin“ randa tą kortelę tarp renginio kortelių ir parodo PIN.
-- CVC mato ir keičia tik redaguojantys „Transportą“ (Transportas → UTA kortelės → kortelė);
-- funkcija jį skaito su service role. Reikia: uta.sql. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.uta_card_cvc (
  card_id    uuid primary key references public.uta_cards(id) on delete cascade,
  cvc        text not null,
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now()
);
alter table public.uta_card_cvc drop constraint if exists uta_card_cvc_cvc_check;
alter table public.uta_card_cvc add constraint uta_card_cvc_cvc_check check (cvc ~ '^[0-9]{3,8}$');
alter table public.uta_card_cvc enable row level security;
drop policy if exists "uta cvc edit" on public.uta_card_cvc;
create policy "uta cvc edit" on public.uta_card_cvc for all to authenticated
  using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.uta_card_cvc from anon;
grant select, insert, update, delete on public.uta_card_cvc to authenticated;
notify pgrst, 'reload schema';
