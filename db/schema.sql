-- =============================================================
-- Growth Capital Workload Monitor — Supabase Schema
-- Run this entire script in the Supabase SQL Editor once.
-- =============================================================

-- ── Tables ────────────────────────────────────────────────────

-- Profiles: one row per auth user, stores name + role
create table public.profiles (
  id         uuid references auth.users(id) on delete cascade primary key,
  email      text not null,
  name       text not null,
  role       text not null default 'Analyst' check (role in ('PL', 'Analyst')),
  created_at timestamptz default now()
);

-- Projects: org-wide (deals + internal projects)
-- "ord" instead of "order" because ORDER is a reserved SQL keyword
create table public.projects (
  id          text primary key,
  name        text not null,
  code        text not null default '',
  type        text not null default 'Project' check (type in ('Deal', 'Project')),
  status      text not null default 'active'  check (status in ('active', 'archived')),
  ord         integer not null default 0,
  archived_at timestamptz,
  created_at  timestamptz default now()
);

-- Records: per-user, per-week workload submissions
create table public.records (
  id           text primary key,
  user_id      uuid references auth.users(id) on delete cascade not null,
  week_start   date not null,
  type         text not null check (type in ('actual', 'forecast')),
  entries      jsonb not null default '[]'::jsonb,
  submitted_at timestamptz,
  updated_at   timestamptz default now(),
  unique (user_id, week_start, type)
);

-- Settings: single-row org-wide config
create table public.settings (
  id                   integer primary key default 1,
  edit_window_days     integer not null default 14,
  hours_per_week_target integer not null default 40,
  constraint settings_single_row check (id = 1)
);
insert into public.settings values (1, 14, 40);

-- ── Trigger: auto-create profile after signup ─────────────────
-- The first user to register is automatically made PL.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
declare
  is_first boolean;
begin
  select not exists (select 1 from public.profiles limit 1) into is_first;
  insert into public.profiles (id, email, name, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    case when is_first then 'PL' else 'Analyst' end
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── Helper function ───────────────────────────────────────────
create or replace function public.is_pl()
returns boolean language sql security definer stable as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'PL'
  )
$$;

-- ── Row Level Security ────────────────────────────────────────
alter table public.profiles enable row level security;
alter table public.projects  enable row level security;
alter table public.records   enable row level security;
alter table public.settings  enable row level security;

-- profiles
create policy "read_all_profiles"
  on public.profiles for select to authenticated using (true);
create policy "insert_own_profile"
  on public.profiles for insert to authenticated with check (id = auth.uid());
create policy "update_profile"
  on public.profiles for update to authenticated using (public.is_pl() or id = auth.uid());
create policy "delete_profile"
  on public.profiles for delete to authenticated using (public.is_pl());

-- projects
create policy "read_projects"
  on public.projects for select to authenticated using (true);
create policy "pl_insert_projects"
  on public.projects for insert to authenticated with check (public.is_pl());
create policy "pl_update_projects"
  on public.projects for update to authenticated using (public.is_pl());
create policy "pl_delete_projects"
  on public.projects for delete to authenticated using (public.is_pl());

-- records
create policy "read_records"
  on public.records for select to authenticated using (true);
create policy "insert_records"
  on public.records for insert to authenticated with check (user_id = auth.uid() or public.is_pl());
create policy "update_records"
  on public.records for update to authenticated using (user_id = auth.uid() or public.is_pl());

-- settings
create policy "read_settings"
  on public.settings for select to authenticated using (true);
create policy "pl_update_settings"
  on public.settings for update to authenticated using (public.is_pl());

-- =============================================================
-- ROLE-CHANGE GUARD
-- (safe to run on an existing database — additive only)
--
-- The update_profile policy above lets a user update their OWN
-- profile (so they can edit their name). On its own that would
-- also let an Analyst set their own role to 'PL' via a direct
-- API call, bypassing the UI. This trigger enforces the real
-- rule: only a PL may change ANY profile's role, and the last
-- remaining PL can never be demoted (prevents org lockout).
-- =============================================================
create or replace function public.guard_role_change()
returns trigger language plpgsql security definer as $$
begin
  -- Role not changing: allow (e.g. user editing their own name).
  if new.role is not distinct from old.role then
    return new;
  end if;

  -- Role is changing: only a PL may do this.
  if not public.is_pl() then
    raise exception 'Only a PL can change a user role.';
  end if;

  -- Never demote the last remaining PL.
  if old.role = 'PL' and new.role <> 'PL'
     and (select count(*) from public.profiles where role = 'PL') <= 1 then
    raise exception 'Cannot demote the last remaining PL.';
  end if;

  return new;
end;
$$;

drop trigger if exists on_profile_role_change on public.profiles;
create trigger on_profile_role_change
  before update on public.profiles
  for each row execute function public.guard_role_change();

-- =============================================================
-- MIGRATION 2 — Company-domain sign-up + access approval
-- (additive & idempotent — safe to run on the live database)
--
--  • Sign-up is limited to @growthcapital.vc email addresses.
--  • New users start as 'pending' and cannot read ANY data until
--    a PL (Team Lead) approves them. The first-ever user is
--    auto-approved so the org is never locked out.
--  • Only a PL can approve/reject (change status) or change roles.
-- =============================================================

-- 1) Approval status on every profile.
alter table public.profiles
  add column if not exists status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected'));

-- Everyone who already exists predates this feature → grandfather them in.
update public.profiles set status = 'approved' where status <> 'approved';

-- 2) Helper: is the calling user approved?
create or replace function public.is_approved()
returns boolean language sql security definer stable as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and status = 'approved'
  )
$$;

-- 3) Sign-up trigger: enforce company domain + set role/status.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
declare
  is_first boolean;
begin
  if lower(split_part(new.email, '@', 2)) <> 'growthcapital.vc' then
    raise exception 'Registration is restricted to @growthcapital.vc email addresses.';
  end if;
  select not exists (select 1 from public.profiles limit 1) into is_first;
  insert into public.profiles (id, email, name, role, status)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    case when is_first then 'PL' else 'Analyst' end,
    case when is_first then 'approved' else 'pending' end
  );
  return new;
end;
$$;

-- 4) Guard: only a PL may change a role OR an approval status,
--    and the last remaining PL can never be demoted.
drop trigger if exists on_profile_role_change on public.profiles;
drop function if exists public.guard_role_change();

create or replace function public.guard_profile_change()
returns trigger language plpgsql security definer as $$
begin
  if new.role is distinct from old.role then
    if not public.is_pl() then
      raise exception 'Only a PL can change a user role.';
    end if;
    if old.role = 'PL' and new.role <> 'PL'
       and (select count(*) from public.profiles where role = 'PL') <= 1 then
      raise exception 'Cannot demote the last remaining PL.';
    end if;
  end if;
  if new.status is distinct from old.status and not public.is_pl() then
    raise exception 'Only a PL can approve or reject a user.';
  end if;
  return new;
end;
$$;

drop trigger if exists on_profile_change on public.profiles;
create trigger on_profile_change
  before update on public.profiles
  for each row execute function public.guard_profile_change();

-- 5) Lock data behind approval. Unapproved users can read only
--    their own profile row (to see their status) — nothing else.
drop policy if exists "read_all_profiles" on public.profiles;
create policy "read_all_profiles"
  on public.profiles for select to authenticated
  using (public.is_approved() or id = auth.uid());

drop policy if exists "read_projects" on public.projects;
create policy "read_projects"
  on public.projects for select to authenticated
  using (public.is_approved());

drop policy if exists "read_records" on public.records;
create policy "read_records"
  on public.records for select to authenticated
  using (public.is_approved());

drop policy if exists "read_settings" on public.settings;
create policy "read_settings"
  on public.settings for select to authenticated
  using (public.is_approved());

-- Unapproved users may not write records either.
drop policy if exists "insert_records" on public.records;
create policy "insert_records"
  on public.records for insert to authenticated
  with check (public.is_approved() and (user_id = auth.uid() or public.is_pl()));

drop policy if exists "update_records" on public.records;
create policy "update_records"
  on public.records for update to authenticated
  using (public.is_approved() and (user_id = auth.uid() or public.is_pl()));
