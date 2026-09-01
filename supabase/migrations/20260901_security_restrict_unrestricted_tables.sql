-- VistaBalayan security hardening for Supabase exposed public schema.
-- Purpose: remove "unrestricted" exposed tables by enabling RLS on application tables,
-- replacing broad client policies with role-scoped policies, and keeping only the
-- intentionally public tourism listing/review surfaces readable to anon users.
--
-- Apply in Supabase SQL Editor with owner/admin privileges, then run the verification
-- query at the end of this file. This migration is idempotent and safe to rerun.

create extension if not exists pgcrypto;

-- -----------------------------------------------------------------------------
-- RBAC helper functions used by RLS policies
-- -----------------------------------------------------------------------------
create or replace function public.current_profile_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role::text
  from public.profiles
  where id = auth.uid()
$$;

create or replace function public.current_establishment_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select establishment_id
  from public.profiles
  where id = auth.uid()
$$;

create or replace function public.is_municipal_officer()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_profile_role() = 'municipal_officer', false)
$$;

create or replace function public.is_establishment_staff()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_profile_role() = 'establishment_staff', false)
$$;

create or replace function public.is_public_tourism_establishment(p_type text, p_status text)
returns boolean
language sql
immutable
as $$
  select coalesce(lower(p_status), '') = 'active'
    and (
      lower(coalesce(p_type, '')) like '%hotel%'
      or lower(coalesce(p_type, '')) like '%inn%'
      or lower(coalesce(p_type, '')) like '%lodge%'
      or lower(coalesce(p_type, '')) like '%resort%'
      or lower(coalesce(p_type, '')) like '%pool%'
      or lower(coalesce(p_type, '')) like '%farm%'
      or lower(coalesce(p_type, '')) like '%tourist%'
      or lower(coalesce(p_type, '')) like '%attraction%'
      or lower(coalesce(p_type, '')) like '%food%'
      or lower(coalesce(p_type, '')) like '%restaurant%'
      or lower(coalesce(p_type, '')) like '%cafe%'
    )
$$;

-- -----------------------------------------------------------------------------
-- Enable RLS on every known exposed application table if it exists.
-- -----------------------------------------------------------------------------
do $$
declare
  table_name text;
begin
  foreach table_name in array array[
    'profiles',
    'establishments',
    'visitor_reports',
    'accommodation_reports',
    'room_occupancy_details',
    'ai_recommendations',
    'ai_anomalies',
    'ai_anomalies_cache',
    'ai_insights_cache',
    'audit_logs',
    'email_otps',
    'notifications',
    'staff',
    'establishment_ratings'
  ] loop
    if exists (
      select 1
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
        and c.relname = table_name
        and c.relkind in ('r', 'p')
    ) then
      execute format('alter table public.%I enable row level security', table_name);
    end if;
  end loop;
end;
$$;

-- -----------------------------------------------------------------------------
-- Remove earlier broad policies that allowed too much client access.
-- -----------------------------------------------------------------------------
do $$
declare
  r record;
begin
  for r in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and (
        policyname in (
          'Authenticated users can read profiles',
          'Authenticated users can update establishments',
          'Public can read establishment ratings',
          'Public can insert establishment ratings',
          'Public can update establishment ratings'
        )
        or policyname like 'Allow all%'
        or policyname like 'Enable read access for all%'
        or policyname like 'Enable insert for authenticated users%'
        or policyname like 'Enable update for authenticated users%'
      )
  loop
    execute format('drop policy if exists %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end;
$$;

-- Remove legacy policies that used the Postgres `public` role, which includes anon
-- users. These policies are the main cause of sensitive report/cache rows remaining
-- readable even after RLS is enabled.
do $$
declare
  r record;
begin
  for r in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in (
        'profiles',
        'visitor_reports',
        'accommodation_reports',
        'room_occupancy_details',
        'ai_recommendations',
        'ai_anomalies',
        'ai_anomalies_cache',
        'ai_insights_cache',
        'audit_logs',
        'email_otps',
        'notifications',
        'staff'
      )
      and roles @> array['public']::name[]
  loop
    execute format('drop policy if exists %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end;
$$;

-- Drop older authenticated catch-all policies on sensitive tables. Scoped policies
-- below replace them.
do $$
declare
  r record;
begin
  for r in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in (
        'profiles',
        'visitor_reports',
        'accommodation_reports',
        'room_occupancy_details',
        'ai_recommendations',
        'ai_anomalies',
        'ai_anomalies_cache',
        'audit_logs',
        'notifications',
        'staff'
      )
      and policyname like 'Allow authenticated users to %'
  loop
    execute format('drop policy if exists %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end;
$$;

-- -----------------------------------------------------------------------------
-- profiles: users read/update themselves; officers manage all profiles.
-- -----------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.profiles') is not null then
    drop policy if exists "Users can read own profile and officers can read all" on public.profiles;
    create policy "Users can read own profile and officers can read all"
      on public.profiles for select
      to authenticated
      using (id = auth.uid() or public.is_municipal_officer());

    drop policy if exists "Users can update own basic profile" on public.profiles;
    create policy "Users can update own basic profile"
      on public.profiles for update
      to authenticated
      using (id = auth.uid())
      with check (id = auth.uid());

    drop policy if exists "Officers manage profiles" on public.profiles;
    create policy "Officers manage profiles"
      on public.profiles for all
      to authenticated
      using (public.is_municipal_officer())
      with check (public.is_municipal_officer());
  end if;
end;
$$;

-- -----------------------------------------------------------------------------
-- establishments: public reads active tourism listings; staff reads/updates own;
-- officers manage all.
-- -----------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.establishments') is not null then
    drop policy if exists "Public can read active tourism establishments" on public.establishments;
    create policy "Public can read active tourism establishments"
      on public.establishments for select
      to anon, authenticated
      using (public.is_public_tourism_establishment(type, status));

    drop policy if exists "Staff can read own establishment" on public.establishments;
    create policy "Staff can read own establishment"
      on public.establishments for select
      to authenticated
      using (id = public.current_establishment_id());

    drop policy if exists "Staff can update own establishment listing" on public.establishments;
    create policy "Staff can update own establishment listing"
      on public.establishments for update
      to authenticated
      using (id = public.current_establishment_id())
      with check (id = public.current_establishment_id());

    drop policy if exists "Officers manage establishments" on public.establishments;
    create policy "Officers manage establishments"
      on public.establishments for all
      to authenticated
      using (public.is_municipal_officer())
      with check (public.is_municipal_officer());
  end if;
end;
$$;

-- -----------------------------------------------------------------------------
-- report tables: officers see/manage all; staff can read/create/update their own
-- establishment's reports. No anon access.
-- -----------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.visitor_reports') is not null then
    drop policy if exists "Visitor reports scoped by role" on public.visitor_reports;
    create policy "Visitor reports scoped by role"
      on public.visitor_reports for select
      to authenticated
      using (public.is_municipal_officer() or establishment_id = public.current_establishment_id());

    drop policy if exists "Staff create visitor reports for own establishment" on public.visitor_reports;
    create policy "Staff create visitor reports for own establishment"
      on public.visitor_reports for insert
      to authenticated
      with check (public.is_municipal_officer() or establishment_id = public.current_establishment_id());

    drop policy if exists "Staff update own pending visitor reports" on public.visitor_reports;
    create policy "Staff update own pending visitor reports"
      on public.visitor_reports for update
      to authenticated
      using (public.is_municipal_officer() or establishment_id = public.current_establishment_id())
      with check (public.is_municipal_officer() or establishment_id = public.current_establishment_id());

    drop policy if exists "Officers review visitor reports" on public.visitor_reports;
    create policy "Officers review visitor reports"
      on public.visitor_reports for update
      to authenticated
      using (public.is_municipal_officer())
      with check (public.is_municipal_officer());
  end if;

  if to_regclass('public.accommodation_reports') is not null then
    drop policy if exists "Accommodation reports scoped by role" on public.accommodation_reports;
    create policy "Accommodation reports scoped by role"
      on public.accommodation_reports for select
      to authenticated
      using (public.is_municipal_officer() or establishment_id = public.current_establishment_id());

    drop policy if exists "Staff create accommodation reports for own establishment" on public.accommodation_reports;
    create policy "Staff create accommodation reports for own establishment"
      on public.accommodation_reports for insert
      to authenticated
      with check (public.is_municipal_officer() or establishment_id = public.current_establishment_id());

    drop policy if exists "Staff update own accommodation reports" on public.accommodation_reports;
    create policy "Staff update own accommodation reports"
      on public.accommodation_reports for update
      to authenticated
      using (public.is_municipal_officer() or establishment_id = public.current_establishment_id())
      with check (public.is_municipal_officer() or establishment_id = public.current_establishment_id());

    drop policy if exists "Officers review accommodation reports" on public.accommodation_reports;
    create policy "Officers review accommodation reports"
      on public.accommodation_reports for update
      to authenticated
      using (public.is_municipal_officer())
      with check (public.is_municipal_officer());
  end if;

  if to_regclass('public.room_occupancy_details') is not null then
    drop policy if exists "Room details scoped through accommodation reports" on public.room_occupancy_details;
    create policy "Room details scoped through accommodation reports"
      on public.room_occupancy_details for select
      to authenticated
      using (
        exists (
          select 1
          from public.accommodation_reports reports
          where reports.id = room_occupancy_details.accommodation_report_id
            and (public.is_municipal_officer() or reports.establishment_id = public.current_establishment_id())
        )
      );

    drop policy if exists "Staff create room details for own reports" on public.room_occupancy_details;
    create policy "Staff create room details for own reports"
      on public.room_occupancy_details for insert
      to authenticated
      with check (
        exists (
          select 1
          from public.accommodation_reports reports
          where reports.id = room_occupancy_details.accommodation_report_id
            and (public.is_municipal_officer() or reports.establishment_id = public.current_establishment_id())
        )
      );
  end if;
end;
$$;

-- -----------------------------------------------------------------------------
-- AI/cache/audit tables: no anon access; authenticated scoped by role where useful.
-- -----------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.ai_recommendations') is not null then
    drop policy if exists "AI recommendations scoped by role" on public.ai_recommendations;
    create policy "AI recommendations scoped by role"
      on public.ai_recommendations for select
      to authenticated
      using (public.is_municipal_officer() or establishment_id is null or establishment_id = public.current_establishment_id());

    drop policy if exists "Authenticated users create AI recommendations" on public.ai_recommendations;
    create policy "Authenticated users create AI recommendations"
      on public.ai_recommendations for insert
      to authenticated
      with check (public.is_municipal_officer() or establishment_id is null or establishment_id = public.current_establishment_id());
  end if;

  if to_regclass('public.ai_anomalies_cache') is not null then
    drop policy if exists "AI anomalies scoped by role" on public.ai_anomalies_cache;
    create policy "AI anomalies scoped by role"
      on public.ai_anomalies_cache for select
      to authenticated
      using (public.is_municipal_officer() or establishment_id is null or establishment_id = public.current_establishment_id());

    drop policy if exists "Authenticated users create AI anomalies" on public.ai_anomalies_cache;
    create policy "Authenticated users create AI anomalies"
      on public.ai_anomalies_cache for insert
      to authenticated
      with check (public.is_municipal_officer() or establishment_id is null or establishment_id = public.current_establishment_id());
  end if;

  if to_regclass('public.ai_insights_cache') is not null then
    drop policy if exists "Authenticated users read AI insights cache" on public.ai_insights_cache;
    create policy "Authenticated users read AI insights cache"
      on public.ai_insights_cache for select
      to authenticated
      using (true);

    drop policy if exists "Authenticated users write AI insights cache" on public.ai_insights_cache;
    create policy "Authenticated users write AI insights cache"
      on public.ai_insights_cache for insert
      to authenticated
      with check (true);
  end if;

  if to_regclass('public.audit_logs') is not null then
    drop policy if exists "Municipal officers can read audit logs" on public.audit_logs;
    create policy "Municipal officers can read audit logs"
      on public.audit_logs for select
      to authenticated
      using (public.is_municipal_officer());

    drop policy if exists "Authenticated users can create audit logs" on public.audit_logs;
    create policy "Authenticated users can create audit logs"
      on public.audit_logs for insert
      to authenticated
      with check (actor_id is null or actor_id = auth.uid() or public.is_municipal_officer());
  end if;

  if to_regclass('public.email_otps') is not null then
    revoke all on public.email_otps from anon, authenticated;
    drop policy if exists "No client access to email otps" on public.email_otps;
    create policy "No client access to email otps"
      on public.email_otps for all
      to anon, authenticated
      using (false)
      with check (false);
  end if;
end;
$$;


-- -----------------------------------------------------------------------------
-- Extra unrestricted objects visible in the Supabase Policies screen screenshot:
-- ai_anomalies, notifications, and staff. These are not used directly by the two
-- current frontends, so they are locked down by default. Where common ownership
-- columns exist, authenticated users may read their own notification/staff rows.
-- -----------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.ai_anomalies') is not null then
    alter table public.ai_anomalies enable row level security;
    drop policy if exists "AI anomalies table officer scoped" on public.ai_anomalies;
    if exists (
      select 1 from information_schema.columns
      where table_schema = 'public' and table_name = 'ai_anomalies' and column_name = 'establishment_id'
    ) then
      create policy "AI anomalies table officer scoped"
        on public.ai_anomalies for select
        to authenticated
        using (public.is_municipal_officer() or establishment_id = public.current_establishment_id());
    else
      create policy "AI anomalies table officer scoped"
        on public.ai_anomalies for select
        to authenticated
        using (public.is_municipal_officer());
    end if;
  end if;

  if to_regclass('public.notifications') is not null then
    alter table public.notifications enable row level security;
    drop policy if exists "Notifications scoped to recipient or officers" on public.notifications;
    if exists (
      select 1 from information_schema.columns
      where table_schema = 'public' and table_name = 'notifications' and column_name = 'user_id'
    ) then
      create policy "Notifications scoped to recipient or officers"
        on public.notifications for select
        to authenticated
        using (public.is_municipal_officer() or user_id = auth.uid());
    elsif exists (
      select 1 from information_schema.columns
      where table_schema = 'public' and table_name = 'notifications' and column_name = 'recipient_id'
    ) then
      create policy "Notifications scoped to recipient or officers"
        on public.notifications for select
        to authenticated
        using (public.is_municipal_officer() or recipient_id = auth.uid());
    else
      create policy "Notifications scoped to recipient or officers"
        on public.notifications for select
        to authenticated
        using (public.is_municipal_officer());
    end if;

    drop policy if exists "Officers create notifications" on public.notifications;
    create policy "Officers create notifications"
      on public.notifications for insert
      to authenticated
      with check (public.is_municipal_officer());
  end if;

  if exists (
    select 1
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relname = 'staff'
      and c.relkind in ('r', 'p')
  ) then
    alter table public.staff enable row level security;
    drop policy if exists "Staff table scoped to user or officers" on public.staff;
    if exists (
      select 1 from information_schema.columns
      where table_schema = 'public' and table_name = 'staff' and column_name = 'user_id'
    ) then
      create policy "Staff table scoped to user or officers"
        on public.staff for select
        to authenticated
        using (public.is_municipal_officer() or user_id = auth.uid());
    elsif exists (
      select 1 from information_schema.columns
      where table_schema = 'public' and table_name = 'staff' and column_name = 'id'
    ) then
      create policy "Staff table scoped to user or officers"
        on public.staff for select
        to authenticated
        using (public.is_municipal_officer() or id = auth.uid());
    else
      create policy "Staff table scoped to user or officers"
        on public.staff for select
        to authenticated
        using (public.is_municipal_officer());
    end if;
  end if;
end;
$$;

-- If staff is a view instead of a table, do not let it bypass underlying RLS.
do $$
begin
  if exists (
    select 1
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'staff' and c.relkind = 'v'
  ) then
    alter view public.staff set (security_invoker = true);
    revoke all on public.staff from anon;
    grant select on public.staff to authenticated;
  end if;
end;
$$;

-- -----------------------------------------------------------------------------
-- Public ratings: raw table protected by RLS and column grants; public clients can
-- see only sanitized fields needed by the tourism page and can write only through
-- submit_establishment_rating().
-- -----------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.establishment_ratings') is not null then
    revoke all on public.establishment_ratings from anon, authenticated;
    grant select (establishment_id, rating, reviewer_name, comment, created_at)
      on public.establishment_ratings to anon, authenticated;

    drop policy if exists "Public can read sanitized establishment ratings" on public.establishment_ratings;
    create policy "Public can read sanitized establishment ratings"
      on public.establishment_ratings for select
      to anon, authenticated
      using (
        exists (
          select 1
          from public.establishments establishments
          where establishments.id = establishment_ratings.establishment_id
            and public.is_public_tourism_establishment(establishments.type, establishments.status)
        )
      );
  end if;
end;
$$;

-- If these review objects are views, make them security-invoker so Supabase does
-- not report them as definer-bypassing RLS views. If a project has old physical
-- tables with these names, enable RLS and allow only sanitized public reads.
do $$
declare
  obj record;
begin
  for obj in
    select c.relname, c.relkind
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relname in ('establishment_rating_summaries', 'establishment_rating_reviews')
  loop
    if obj.relkind = 'v' then
      execute format('alter view public.%I set (security_invoker = true)', obj.relname);
      execute format('grant select on public.%I to anon, authenticated', obj.relname);
    elsif obj.relkind in ('r', 'p') then
      execute format('alter table public.%I enable row level security', obj.relname);
      execute format('grant select on public.%I to anon, authenticated', obj.relname);
      execute format('drop policy if exists "Public can read sanitized rating object" on public.%I', obj.relname);
      execute format(
        'create policy "Public can read sanitized rating object" on public.%I for select to anon, authenticated using (exists (select 1 from public.establishments e where e.id = establishment_id and public.is_public_tourism_establishment(e.type, e.status)))',
        obj.relname
      );
    end if;
  end loop;
end;
$$;

-- Keep the rating RPC as the only public write path.
do $$
begin
  if to_regprocedure('public.submit_establishment_rating(uuid,text,integer,text,text)') is not null then
    revoke all on function public.submit_establishment_rating(uuid,text,integer,text,text) from public;
    grant execute on function public.submit_establishment_rating(uuid,text,integer,text,text) to anon, authenticated;
  end if;
end;
$$;

notify pgrst, 'reload schema';

-- -----------------------------------------------------------------------------
-- Verification query: should return zero rows for base application tables with
-- rls_disabled = true. Views are listed separately for visibility.
-- -----------------------------------------------------------------------------
select
  n.nspname as schema_name,
  c.relname as object_name,
  case c.relkind when 'r' then 'table' when 'p' then 'partitioned table' when 'v' then 'view' when 'm' then 'materialized view' else c.relkind::text end as object_type,
  case when c.relkind in ('r','p') then not c.relrowsecurity else null end as rls_disabled
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relname in (
    'profiles', 'establishments', 'visitor_reports', 'accommodation_reports',
    'room_occupancy_details', 'ai_recommendations', 'ai_anomalies', 'ai_anomalies_cache',
    'ai_insights_cache', 'audit_logs', 'email_otps', 'notifications', 'staff', 'establishment_ratings',
    'establishment_rating_summaries', 'establishment_rating_reviews'
  )
order by object_type, object_name;
