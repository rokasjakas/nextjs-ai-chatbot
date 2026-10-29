-- Prieigų patikrinimas (tik skaito, nieko nekeičia): ką kiekvienas lygis gali kiekviename puslapyje (role_permissions)
-- ir ar Office kur nors turi mažiau nei Tech. Paleidžiama per „SQL paleidimas“.
select 'lygis' as k, role || ' · ' || string_agg(section || '=' || case when can_edit then 'edit' when can_view then 'view' else '-' end, ', ' order by section) as v
  from public.role_permissions group by role
union all
select 'office<tech', coalesce(string_agg(t.section || ' (tech ' || case when t.can_edit then 'edit' else 'view' end || ', office ' ||
    coalesce(case when o.can_edit then 'edit' when o.can_view then 'view' end, 'nieko') || ')', ', ' order by t.section), 'nėra')
  from public.role_permissions t
  left join public.role_permissions o on o.role = 'office' and o.section = t.section
  where t.role = 'tech' and (t.can_view or t.can_edit)
    and (o.section is null or (t.can_edit and not o.can_edit) or (t.can_view and not o.can_view and not o.can_edit))
union all
select 'nariai', role || ' · ' || count(*) from public.profiles group by role;
