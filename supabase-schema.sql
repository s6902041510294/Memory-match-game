-- Memory Match: Supabase schema
-- Run this whole script in Supabase Dashboard > SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('teacher','student')),
  display_name text not null,
  created_at timestamptz not null default now()
);


-- Security-definer helper avoids recursive RLS checks on profiles.
create or replace function public.is_teacher()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'teacher'
  );
$$;

grant execute on function public.is_teacher() to anon, authenticated;


create table if not exists public.games (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  icon text not null default '🎯',
  size jsonb not null default '{"rows":3,"cols":4}'::jsonb,
  pairs jsonb not null default '[]'::jsonb,
  published boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.scores (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references auth.users(id) on delete cascade,
  student_name text not null,
  game_id uuid references public.games(id) on delete set null,
  game_name text not null,
  score integer not null default 0,
  max_score integer not null default 0,
  attempts integer not null default 0,
  accuracy integer not null default 0,
  seconds integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists games_created_at_idx on public.games(created_at desc);
create index if not exists scores_game_id_idx on public.scores(game_id);
create index if not exists scores_student_id_idx on public.scores(student_id);
create index if not exists scores_created_at_idx on public.scores(created_at desc);

alter table public.profiles enable row level security;
alter table public.games enable row level security;
alter table public.scores enable row level security;

drop policy if exists "profile read self or teacher" on public.profiles;
create policy "profile read self or teacher" on public.profiles
for select to authenticated
using (
  id = auth.uid() or public.is_teacher()
);

drop policy if exists "student create own profile" on public.profiles;
create policy "student create own profile" on public.profiles
for insert to authenticated
with check (id = auth.uid() and role = 'student');

drop policy if exists "student update own profile" on public.profiles;
create policy "student update own profile" on public.profiles
for update to authenticated
using (id = auth.uid() and role = 'student')
with check (id = auth.uid() and role = 'student');

drop policy if exists "read published games" on public.games;
create policy "read published games" on public.games
for select to anon, authenticated
using (
  published = true or public.is_teacher()
);

drop policy if exists "teacher create games" on public.games;
create policy "teacher create games" on public.games
for insert to authenticated
with check (
  created_by = auth.uid()
  and public.is_teacher()
);

drop policy if exists "teacher update games" on public.games;
create policy "teacher update games" on public.games
for update to authenticated
using (public.is_teacher())
with check (public.is_teacher());

drop policy if exists "teacher delete games" on public.games;
create policy "teacher delete games" on public.games
for delete to authenticated
using (public.is_teacher());

drop policy if exists "students insert own scores" on public.scores;
create policy "students insert own scores" on public.scores
for insert to authenticated
with check (
  student_id = auth.uid()
  and exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'student')
);

drop policy if exists "read own scores or all scores as teacher" on public.scores;
create policy "read own scores or all scores as teacher" on public.scores
for select to authenticated
using (student_id = auth.uid() or public.is_teacher());
