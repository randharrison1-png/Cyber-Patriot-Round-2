-- LeadHub public paste storage (Supabase SQL Editor).
-- Anyone knowing an unguessable 36-character link can read and edit that paste.
-- Direct table SELECT, INSERT, UPDATE and DELETE are revoked from public clients.
-- IMPORTANT: anonymous creation still invites spam; consider CAPTCHA, quotas, and
-- rate limiting before using this with large public audiences.

create table if not exists public.leadhub_pastes (
  slug text primary key check (slug ~ '^[0-9a-f]{36}$'),
  title text not null default 'Untitled report'
    check (char_length(title) between 1 and 100),
  content text not null check (char_length(content) <= 200000),
  revision integer not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.leadhub_pastes enable row level security;
-- Having no direct RLS policies deliberately denies all direct table access.
revoke all on table public.leadhub_pastes from public, anon, authenticated;

create or replace function public.get_paste(p_slug text)
returns setof public.leadhub_pastes
language sql
stable
security definer
set search_path = ''
as $$
  select p.*
  from public.leadhub_pastes as p
  where p.slug = p_slug
  limit 1;
$$;

create or replace function public.create_paste(
  p_slug text,
  p_title text,
  p_content text
)
returns setof public.leadhub_pastes
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_slug is null or p_slug !~ '^[0-9a-f]{36}$' then
    raise exception 'Invalid report identifier';
  end if;
  if p_title is null or char_length(trim(p_title)) < 1 or char_length(p_title) > 100 then
    raise exception 'Title must be 1–100 characters';
  end if;
  if p_content is null or char_length(p_content) > 200000 or char_length(trim(p_content)) = 0 then
    raise exception 'Report must contain text under 200000 characters';
  end if;
  return query
    insert into public.leadhub_pastes(slug, title, content)
    values (p_slug, p_title, p_content)
    returning *;
end;
$$;

create or replace function public.update_paste(
  p_slug text,
  p_expected_revision integer,
  p_title text,
  p_content text
)
returns setof public.leadhub_pastes
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_slug is null or p_slug !~ '^[0-9a-f]{36}$' then
    raise exception 'Invalid report identifier';
  end if;
  if p_expected_revision is null or p_expected_revision < 1 then
    raise exception 'Invalid revision';
  end if;
  if p_title is null or char_length(trim(p_title)) < 1 or char_length(p_title) > 100 then
    raise exception 'Title must be 1–100 characters';
  end if;
  if p_content is null or char_length(p_content) > 200000 or char_length(trim(p_content)) = 0 then
    raise exception 'Report must contain text under 200000 characters';
  end if;
  return query
    update public.leadhub_pastes
    set title = p_title,
        content = p_content,
        revision = revision + 1,
        updated_at = now()
    where slug = p_slug and revision = p_expected_revision
    returning *;
end;
$$;

revoke all on function public.get_paste(text) from public, anon, authenticated;
revoke all on function public.create_paste(text,text,text) from public, anon, authenticated;
revoke all on function public.update_paste(text,integer,text,text) from public, anon, authenticated;

grant usage on schema public to anon, authenticated;
grant execute on function public.get_paste(text) to anon, authenticated;
grant execute on function public.create_paste(text,text,text) to anon, authenticated;
grant execute on function public.update_paste(text,integer,text,text) to anon, authenticated;
