-- Office – lygiu aukščiau už Tech: kiekviename puslapyje Office gauna bent tiek, kiek turi Tech (role_permissions).
-- Tik PRIDEDA teisių (niekas neatimama): kur Tech gali žiūrėti – Office irgi, kur Tech gali redaguoti – Office irgi.
-- Paleidžiama per „SQL paleidimas“. Saugu paleisti pakartotinai.
insert into public.role_permissions (role, section, can_view, can_edit)
select 'office', t.section, t.can_view or t.can_edit or coalesce(o.can_view, false), t.can_edit or coalesce(o.can_edit, false)
  from public.role_permissions t
  left join public.role_permissions o on o.role = 'office' and o.section = t.section
 where t.role = 'tech'
on conflict (role, section) do update set can_view = excluded.can_view, can_edit = excluded.can_edit;

select 'office' as k, string_agg(section || '=' || case when can_edit then 'edit' when can_view then 'view' else '-' end, ', ' order by section) as v
  from public.role_permissions where role = 'office'
union all
select 'office<tech', coalesce(string_agg(t.section, ', '), 'nėra')
  from public.role_permissions t join public.role_permissions o on o.role = 'office' and o.section = t.section
 where t.role = 'tech' and ((t.can_edit and not o.can_edit) or (t.can_view and not (o.can_view or o.can_edit)));
