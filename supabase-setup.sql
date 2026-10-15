-- Run this in Supabase SQL Editor before testing chat.
-- This creates a minimal searchable profile directory and the messages table.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
-- Profile read policy is created after the messages table below.

create or replace function public.ntk3_create_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email)
  values (new.id, lower(new.email))
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists ntk3_auth_user_profile on auth.users;
create trigger ntk3_auth_user_profile
after insert or update of email on auth.users
for each row execute procedure public.ntk3_create_profile();

-- Backfill users who registered before this trigger was installed.
insert into public.profiles (id, email)
select id, lower(email) from auth.users where email is not null
on conflict (id) do update set email = excluded.email;

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  ciphertext text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '7 days'),
  delivered_at timestamptz
);

alter table public.profiles enable row level security;
drop policy if exists "Authenticated users can find profiles by email" on public.profiles;
drop policy if exists "Users can see self and chat partners" on public.profiles;
create policy "Users can see self and chat partners"
on public.profiles for select to authenticated
using (
  id = (select auth.uid()) or exists (
    select 1 from public.messages m
    where (m.sender_id = (select auth.uid()) and m.recipient_id = profiles.id)
       or (m.recipient_id = (select auth.uid()) and m.sender_id = profiles.id)
  )
);

alter table public.messages enable row level security;
drop policy if exists "Users can send messages as themselves" on public.messages;
drop policy if exists "Participants can read their messages" on public.messages;
drop policy if exists "Recipients can mark messages delivered" on public.messages;
create policy "Users can send messages as themselves"
on public.messages for insert to authenticated
with check (sender_id = (select auth.uid()) and sender_id <> recipient_id);
create policy "Participants can read their messages"
on public.messages for select to authenticated
using (sender_id = (select auth.uid()) or recipient_id = (select auth.uid()));
create policy "Recipients can mark messages delivered"
on public.messages for update to authenticated
using (recipient_id = (select auth.uid()))
with check (recipient_id = (select auth.uid()));
create index if not exists messages_expiry_idx on public.messages (expires_at);
create index if not exists messages_participants_created_idx on public.messages (sender_id, recipient_id, created_at);

-- Restrict delivery updates to the delivered_at column only.
revoke update on table public.messages from authenticated;
grant update (delivered_at) on table public.messages to authenticated;


-- Exact-email lookup: the profiles table itself is not a public directory.
create or replace function public.ntk3_find_profile_by_email(p_email text)
returns table(id uuid, email text)
language sql
security definer
set search_path = ''
as $$
  select p.id, p.email
  from public.profiles p
  where auth.uid() is not null and lower(p.email) = lower(trim(p_email))
  limit 1;
$$;
revoke all on function public.ntk3_find_profile_by_email(text) from public;
grant execute on function public.ntk3_find_profile_by_email(text) to authenticated;
