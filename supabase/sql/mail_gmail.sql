-- ============================================================
-- El. paštas: „Gauti per Gmail“
--  * pašto serveris (serveriai.lt) persiunčia laiškus į Gmail; programa juos skaito iš Gmail
--    (greita, dideli laiškai atsidaro iš karto), o siunčia kaip anksčiau – iš @eventsolutions.lt
--  * Gmail programos slaptažodis saugomas užšifruotas (kaip ir pašto slaptažodis)
-- Reikia: mail.sql ir „mail“ funkcija v15 (supabase functions deploy mail).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.mail_accounts add column if not exists reader jsonb;
notify pgrst, 'reload schema';

-- Gmail skirtukai (Pagrindiniai, Reklamos, Socialiniai, Naujienos, Forumai): kiekvieno laiško kategorija
alter table public.mail_index add column if not exists cat text;
create index if not exists mail_index_cat on public.mail_index (user_id, folder, cat, date desc nulls last);
notify pgrst, 'reload schema';
