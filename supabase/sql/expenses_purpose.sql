-- ============================================================
-- Išlaidos → Kuras: tikslas – darbo ar asmeninis
--  * purpose 'work' (numatyta) – darbo išlaida, kaip iki šiol (komentaras būtinas, gali būti kompensuojama)
--  * purpose 'personal' – asmeniniais tikslais: nepagrindžia darbo pylimo; mokėta UTA kortele –
--    pylimas pažymimas asmeniniu (uta_personal) ir atimamas iš balanso
-- Reikia: expenses.sql. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.expenses add column if not exists purpose text not null default 'work';
do $$ begin
  alter table public.expenses add constraint expenses_purpose_check check (purpose in ('work', 'personal'));
exception when duplicate_object then null; end $$;
notify pgrst, 'reload schema';
