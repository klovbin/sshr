-- sshr sync store in a Supabase project, run it once in the SQL editor.
-- It sets the key only in a project that has none, an old copy run again
-- never brings back a key that sshr sync supabase-sql --replace took out.
-- The objects live in schema sshr, which the Data API does not expose, the
-- publishable key reaches them only through the sshr_* functions below,
-- each checks the sshr key a device sends before it does anything.

create schema if not exists sshr;
revoke all on schema sshr from public, anon, authenticated;

create table if not exists sshr.objects (
  name text collate "C" primary key check (name ~ '^(account|devices/[0-9a-f]{32}|envelopes/[0-9a-f]{32}/[0-9]{10}|blobs/[0-9a-f]{64}|manifests/[0-9]{20}|probe/[0-9a-f]{16})$'),
  data bytea not null,
  size int generated always as (octet_length(data)) stored
);
-- the data is encrypted, compressing it only costs time
alter table sshr.objects alter column data set storage external;
alter table sshr.objects enable row level security;

create table if not exists sshr.keys (hash bytea primary key);
alter table sshr.keys enable row level security;
revoke all on all tables in schema sshr from public, anon, authenticated;

create or replace function sshr.check_key() returns void
language plpgsql security definer set search_path = '' as $$
declare k text := coalesce(current_setting('request.headers', true)::json ->> 'x-sshr-key', '');
begin
  if not exists (select 1 from sshr.keys where hash = sha256(convert_to(k, 'UTF8'))) then
    raise sqlstate 'PT403' using message = 'sshr key refused';
  end if;
end $$;

create or replace function public.sshr_get(p_name text, p_max int) returns text
language plpgsql security definer set search_path = '' set statement_timeout = '30s' as $$
declare d bytea; s int;
begin
  perform sshr.check_key();
  -- the size first, a presence check with p_max 0 reads no data
  select o.size into s from sshr.objects o where o.name = p_name;
  if not found then
    raise sqlstate 'PT404' using message = 'not found';
  end if;
  if s > coalesce(p_max, 0) then
    raise sqlstate 'PT413' using message = 'too large';
  end if;
  select o.data into d from sshr.objects o where o.name = p_name;
  return encode(d, 'base64');
end $$;

create or replace function public.sshr_put(p_name text, p_data text) returns void
language plpgsql security definer set search_path = '' set statement_timeout = '30s' as $$
begin
  perform sshr.check_key();
  insert into sshr.objects (name, data) values (p_name, decode(p_data, 'base64'))
  on conflict (name) do update set data = excluded.data;
end $$;

-- the same bytes again succeed, a retry after a lost answer must not read
-- the device's own write as one of another device
create or replace function public.sshr_create(p_name text, p_data text) returns void
language plpgsql security definer set search_path = '' set statement_timeout = '30s' as $$
declare d bytea;
begin
  perform sshr.check_key();
  -- after the key check, a caller without the key gets no decoding work
  d := decode(p_data, 'base64');
  insert into sshr.objects (name, data) values (p_name, d) on conflict (name) do nothing;
  if not found then
    if exists (select 1 from sshr.objects o where o.name = p_name and o.data = d) then
      return;
    end if;
    raise sqlstate 'PT409' using message = 'exists';
  end if;
end $$;

create or replace function public.sshr_delete(p_name text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform sshr.check_key();
  delete from sshr.objects o where o.name = p_name;
end $$;

create or replace function public.sshr_list(p_prefix text, p_after text) returns table (name text)
language plpgsql security definer set search_path = '' as $$
begin
  perform sshr.check_key();
  return query select o.name::text from sshr.objects o
    where starts_with(o.name, p_prefix) and o.name > coalesce(p_after, '')
    order by o.name limit 1000;
end $$;

revoke execute on function sshr.check_key() from public, anon, authenticated;
revoke execute on function public.sshr_get(text, int), public.sshr_put(text, text), public.sshr_create(text, text),
  public.sshr_delete(text), public.sshr_list(text, text) from public, anon, authenticated;
grant execute on function public.sshr_get(text, int), public.sshr_put(text, text), public.sshr_create(text, text),
  public.sshr_delete(text), public.sshr_list(text, text) to anon;

-- the key of this account, only its sha256 is stored, set only while the
-- project has no key, a key change goes through --replace
insert into sshr.keys (hash) select '\x{{KEY_HASH}}' where not exists (select 1 from sshr.keys);

notify pgrst, 'reload schema';
