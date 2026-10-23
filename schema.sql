-- YP4T Connect — Supabase database setup
-- Paste this whole file into Supabase → SQL Editor → New query → Run. Run it once.

create extension if not exists pgcrypto;

-- ───────────────────────── Members ─────────────────────────
create table if not exists public.members (
  id            uuid primary key references auth.users(id) on delete cascade,
  full_name     text not null check (char_length(full_name) between 2 and 80),
  profession    text not null check (char_length(profession) between 2 and 60),
  state         text not null,
  lga           text not null,
  ward          text not null default '',
  photo_url     text,
  has_pvc       boolean not null default false,
  canvass       boolean not null default false,
  listed        boolean not null default true,
  status        text not null default 'pending' check (status in ('pending','approved','rejected')),
  role          text not null default 'member' check (role in ('member','ward','lga','state','national','admin')),
  ref_code      text unique not null default substr(md5(gen_random_uuid()::text), 1, 8),
  invited_with  text,
  referred_by   uuid references public.members(id) on delete set null,
  created_at    timestamptz not null default now()
);
create index if not exists members_area_idx on public.members (state, lga, ward);
create index if not exists members_ref_idx on public.members (referred_by);

-- Private contact details: visible only to the member and their coordinators
create table if not exists public.member_private (
  id          uuid primary key references public.members(id) on delete cascade,
  phone       text not null check (char_length(phone) between 7 and 20),
  email       text,
  consent_at  timestamptz not null default now()
);

-- ───────────────────────── Helper functions ─────────────────────────
create or replace function public.is_approved() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members where id = auth.uid() and status = 'approved');
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members where id = auth.uid() and status = 'approved' and role in ('admin','national'));
$$;

-- Does the current user coordinate this area (or a bigger area containing it)?
create or replace function public.manages(p_state text, p_lga text, p_ward text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from members m
    where m.id = auth.uid() and m.status = 'approved' and (
         m.role in ('admin','national')
      or (m.role = 'state' and m.state = p_state)
      or (m.role = 'lga'   and m.state = p_state and m.lga = p_lga)
      or (m.role = 'ward'  and m.state = p_state and m.lga = p_lga and lower(m.ward) = lower(coalesce(p_ward,'')))
    )
  );
$$;

-- ───────────────────────── Sign-up and approval rules ─────────────────────────
create or replace function public.members_before_insert() returns trigger
language plpgsql security definer set search_path = public as $$
declare inviter members%rowtype;
begin
  new.status := 'pending';
  new.role := 'member';
  new.referred_by := null;
  new.ward := initcap(trim(new.ward));
  -- The very first person to join becomes Super Admin (do this yourself right after setup)
  if not exists (select 1 from members) then
    new.status := 'approved';
    new.role := 'admin';
    return new;
  end if;
  if new.invited_with is not null then
    select * into inviter from members where ref_code = new.invited_with;
    if found then
      new.referred_by := inviter.id;
      -- Invited by an approved member → approved automatically
      if inviter.status = 'approved' then new.status := 'approved'; end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists members_before_insert on public.members;
create trigger members_before_insert before insert on public.members
for each row execute function public.members_before_insert();

create or replace function public.members_before_update() returns trigger
language plpgsql security definer set search_path = public as $$
declare me members%rowtype;
begin
  select * into me from members where id = auth.uid();
  new.ref_code := old.ref_code;
  new.referred_by := old.referred_by;
  new.invited_with := old.invited_with;
  new.created_at := old.created_at;
  new.ward := initcap(trim(new.ward));
  -- Only coordinators of this area may change approval status
  if new.status is distinct from old.status and not manages(old.state, old.lga, old.ward) then
    new.status := old.status;
  end if;
  -- Role changes: Super Admin / National appoint anyone; State Coordinators appoint LGA and ward coordinators in their state
  if new.role is distinct from old.role then
    if not (
         is_admin()
      or (me.status = 'approved' and me.role = 'state' and me.state = old.state and new.role in ('member','lga','ward') and old.role in ('member','lga','ward'))
    ) then
      new.role := old.role;
    end if;
  end if;
  -- Nobody can make themselves admin/national
  if new.id = auth.uid() and new.role is distinct from old.role and old.role <> 'admin' then
    new.role := old.role;
  end if;
  return new;
end $$;
drop trigger if exists members_before_update on public.members;
create trigger members_before_update before update on public.members
for each row execute function public.members_before_update();

-- ───────────────────────── Row level security ─────────────────────────
alter table public.members enable row level security;
alter table public.member_private enable row level security;

drop policy if exists members_select on public.members;
create policy members_select on public.members for select using (
  id = auth.uid()
  or (status = 'approved' and listed and public.is_approved())
  or public.manages(state, lga, ward)
);
drop policy if exists members_insert on public.members;
create policy members_insert on public.members for insert with check (id = auth.uid());
drop policy if exists members_update on public.members;
create policy members_update on public.members for update using (
  id = auth.uid() or public.manages(state, lga, ward)
);
drop policy if exists members_delete on public.members;
create policy members_delete on public.members for delete using (id = auth.uid() or public.is_admin());

drop policy if exists private_select on public.member_private;
create policy private_select on public.member_private for select using (
  id = auth.uid()
  or exists (select 1 from public.members m where m.id = member_private.id and public.manages(m.state, m.lga, m.ward))
);
drop policy if exists private_insert on public.member_private;
create policy private_insert on public.member_private for insert with check (id = auth.uid());
drop policy if exists private_update on public.member_private;
create policy private_update on public.member_private for update using (id = auth.uid());

-- ───────────────────────── Map numbers (counts only, never names) ─────────────────────────
create or replace function public.public_total() returns bigint
language sql stable security definer set search_path = public as $$
  select count(*) from members where status = 'approved';
$$;

create or replace function public.area_stats()
returns table (state text, lga text, ward text, members bigint, pvc bigint, canvass bigint, new_7d bigint)
language sql stable security definer set search_path = public as $$
  select m.state, m.lga, m.ward, count(*), count(*) filter (where m.has_pvc), count(*) filter (where m.canvass),
         count(*) filter (where m.created_at > now() - interval '7 days')
  from members m
  where m.status = 'approved' and (select public.is_approved())
  group by 1, 2, 3;
$$;

create or replace function public.recent_joins()
returns table (first_name text, profession text, state text, lga text, created_at timestamptz)
language sql stable security definer set search_path = public as $$
  select split_part(full_name, ' ', 1), profession, state, lga, created_at
  from members where status = 'approved' and (select public.is_approved())
  order by created_at desc limit 12;
$$;

create or replace function public.top_recruiters()
returns table (member_id uuid, first_name text, state text, lga text, recruits bigint)
language sql stable security definer set search_path = public as $$
  select r.id, split_part(r.full_name, ' ', 1), r.state, r.lga, count(m.id)
  from members m join members r on r.id = m.referred_by
  where m.status = 'approved' and (select public.is_approved())
  group by r.id, r.full_name, r.state, r.lga
  order by count(m.id) desc limit 20;
$$;

-- National and State Coordinators, shown on the home screen (public)
create or replace function public.public_leaders()
returns table (id uuid, full_name text, role text, state text, photo_url text)
language sql stable security definer set search_path = public as $$
  select id, full_name, role, state, photo_url from members
  where status = 'approved' and role in ('national','state')
  order by case role when 'national' then 0 else 1 end, state;
$$;

-- All coordinators for an area (members only)
create or replace function public.area_coordinators(p_state text)
returns table (id uuid, full_name text, role text, state text, lga text, ward text, photo_url text)
language sql stable security definer set search_path = public as $$
  select id, full_name, role, state, lga, ward, photo_url from members
  where status = 'approved' and role in ('national','state','lga','ward')
    and (role = 'national' or state = p_state) and (select public.is_approved());
$$;

-- ───────────────────────── Chat ─────────────────────────
-- Rooms: 'ward:<state>|<lga>|<ward>', 'state:<state>', 'dm:<uuid>:<uuid>' (ids sorted)
create table if not exists public.messages (
  id           bigint generated always as identity primary key,
  room         text not null check (char_length(room) < 300),
  sender       uuid not null default auth.uid() references public.members(id) on delete cascade,
  sender_name  text,
  sender_photo text,
  body         text not null check (char_length(body) between 1 and 1000),
  created_at   timestamptz not null default now()
);
create index if not exists messages_room_idx on public.messages (room, created_at);

create or replace function public.can_access_room(p_room text) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare me members%rowtype; parts text[];
begin
  select * into me from members where id = auth.uid();
  if not found or me.status <> 'approved' then return false; end if;
  if p_room like 'dm:%' then
    return auth.uid()::text in (split_part(p_room, ':', 2), split_part(p_room, ':', 3));
  elsif p_room like 'ward:%' then
    parts := string_to_array(substr(p_room, 6), '|');
    return (me.state = parts[1] and me.lga = parts[2] and lower(me.ward) = lower(parts[3]))
        or manages(parts[1], parts[2], parts[3]);
  elsif p_room like 'state:%' then
    return me.state = substr(p_room, 7) or manages(substr(p_room, 7), null, null);
  end if;
  return false;
end $$;

create or replace function public.messages_before_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.sender := auth.uid();
  select full_name, photo_url into new.sender_name, new.sender_photo from members where id = auth.uid();
  new.created_at := now();
  return new;
end $$;
drop trigger if exists messages_before_insert on public.messages;
create trigger messages_before_insert before insert on public.messages
for each row execute function public.messages_before_insert();

alter table public.messages enable row level security;
drop policy if exists messages_select on public.messages;
create policy messages_select on public.messages for select using (public.can_access_room(room));
drop policy if exists messages_insert on public.messages;
create policy messages_insert on public.messages for insert with check (public.can_access_room(room));
drop policy if exists messages_delete on public.messages;
create policy messages_delete on public.messages for delete using (sender = auth.uid() or public.is_admin());

-- People I have private chats with
create or replace function public.dm_partners()
returns table (room text, partner uuid, partner_name text, partner_photo text, last_body text, last_at timestamptz)
language sql stable security definer set search_path = public as $$
  with mine as (
    select distinct on (room) room, body, created_at from messages
    where room like 'dm:%' and auth.uid()::text in (split_part(room, ':', 2), split_part(room, ':', 3))
    order by room, created_at desc
  )
  select mine.room, p.id, p.full_name, p.photo_url, mine.body, mine.created_at
  from mine join members p on p.id::text = case when split_part(mine.room, ':', 2) = auth.uid()::text
                                                then split_part(mine.room, ':', 3) else split_part(mine.room, ':', 2) end
  order by mine.created_at desc;
$$;

-- ───────────────────────── Door-to-door outings ─────────────────────────
create table if not exists public.outings (
  id          bigint generated always as identity primary key,
  state       text not null,
  lga         text not null,
  ward        text not null,
  title       text not null check (char_length(title) between 3 and 120),
  place       text not null check (char_length(place) between 3 and 160),
  starts_at   timestamptz not null,
  created_by  uuid default auth.uid() references public.members(id) on delete set null,
  created_at  timestamptz not null default now()
);
create table if not exists public.outing_rsvps (
  outing_id  bigint references public.outings(id) on delete cascade,
  member_id  uuid default auth.uid() references public.members(id) on delete cascade,
  primary key (outing_id, member_id)
);
alter table public.outings enable row level security;
alter table public.outing_rsvps enable row level security;
drop policy if exists outings_select on public.outings;
create policy outings_select on public.outings for select using (
  public.is_approved() and (
    exists (select 1 from public.members m where m.id = auth.uid() and m.state = outings.state)
    or public.manages(state, lga, ward))
);
drop policy if exists outings_insert on public.outings;
create policy outings_insert on public.outings for insert with check (public.manages(state, lga, ward));
drop policy if exists outings_delete on public.outings;
create policy outings_delete on public.outings for delete using (public.manages(state, lga, ward));
drop policy if exists rsvps_select on public.outing_rsvps;
create policy rsvps_select on public.outing_rsvps for select using (public.is_approved());
drop policy if exists rsvps_insert on public.outing_rsvps;
create policy rsvps_insert on public.outing_rsvps for insert with check (member_id = auth.uid() and public.is_approved());
drop policy if exists rsvps_delete on public.outing_rsvps;
create policy rsvps_delete on public.outing_rsvps for delete using (member_id = auth.uid());

-- ───────────────────────── Renewed Hope projects (every entry needs a source) ─────────────────────────
create table if not exists public.projects (
  id          bigint generated always as identity primary key,
  state       text not null,
  title       text not null check (char_length(title) between 3 and 160),
  category    text not null default 'Infrastructure',
  summary     text check (char_length(summary) <= 600),
  source_url  text not null check (source_url ~* '^https://'),
  created_by  uuid default auth.uid() references public.members(id) on delete set null,
  created_at  timestamptz not null default now()
);
alter table public.projects enable row level security;
drop policy if exists projects_select on public.projects;
create policy projects_select on public.projects for select using (true);
drop policy if exists projects_insert on public.projects;
create policy projects_insert on public.projects for insert with check (public.manages(state, null, null) or public.is_admin());
drop policy if exists projects_delete on public.projects;
create policy projects_delete on public.projects for delete using (public.manages(state, null, null) or public.is_admin());

-- People most active in an area, for picking new coordinators
create or replace function public.coordinator_candidates(p_state text)
returns table (id uuid, full_name text, profession text, lga text, ward text, role text, recruits bigint, canvass boolean, outings bigint, messages bigint, score bigint)
language sql stable security definer set search_path = public as $$
  select m.id, m.full_name, m.profession, m.lga, m.ward, m.role,
    (select count(*) from members x where x.referred_by = m.id and x.status = 'approved') as recruits,
    m.canvass,
    (select count(*) from outing_rsvps o where o.member_id = m.id) as outings,
    (select count(*) from messages g where g.sender = m.id) as messages,
    (select count(*) from members x where x.referred_by = m.id and x.status = 'approved') * 5
      + (case when m.canvass then 10 else 0 end)
      + (select count(*) from outing_rsvps o where o.member_id = m.id) * 4
      + least((select count(*) from messages g where g.sender = m.id), 30) as score
  from members m
  where m.status = 'approved' and m.state = p_state and public.manages(p_state, null, null)
     or (m.status = 'approved' and m.state = p_state and public.is_admin())
  order by score desc limit 40;
$$;

-- ───────────────────────── Permissions for the website ─────────────────────────
grant execute on function public.public_total(), public.public_leaders() to anon, authenticated;
grant execute on function public.area_stats(), public.recent_joins(), public.top_recruiters(),
  public.area_coordinators(text), public.coordinator_candidates(text), public.dm_partners() to authenticated;

-- ───────────────────────── Live updates ─────────────────────────
do $$ begin
  begin alter publication supabase_realtime add table public.messages; exception when others then null; end;
  begin alter publication supabase_realtime add table public.members; exception when others then null; end;
end $$;

-- ───────────────────────── Photo storage ─────────────────────────
insert into storage.buckets (id, name, public) values ('photos', 'photos', true)
on conflict (id) do nothing;
drop policy if exists photos_upload on storage.objects;
create policy photos_upload on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists photos_update on storage.objects;
create policy photos_update on storage.objects for update to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
