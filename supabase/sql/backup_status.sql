-- Paskutinės atsarginės kopijos būsena (tik skaito): ką įrašė „Atsarginės kopijos“ darbas.
select key, value::text from public.app_config where key = 'backup';
