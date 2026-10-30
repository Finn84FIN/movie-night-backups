-- Standalone synthetic contracts for backup tests. No application migrations,
-- production schema export, records or provider settings are included here.
DROP SCHEMA public, auth, storage, extensions CASCADE;
CREATE SCHEMA public;
CREATE SCHEMA auth;
CREATE SCHEMA storage;
CREATE SCHEMA extensions;
CREATE SCHEMA IF NOT EXISTS supabase_migrations;
CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
CREATE TABLE auth.users (
  id uuid PRIMARY KEY, email text, encrypted_password text,
  aud text, role text, email_confirmed_at timestamptz
);
CREATE TABLE auth.identities (
  id uuid PRIMARY KEY, user_id uuid REFERENCES auth.users(id),
  provider_id text, provider text, identity_data jsonb
);
CREATE TABLE public.profiles (id uuid PRIMARY KEY REFERENCES auth.users(id), timezone text);
CREATE TABLE public.movie_spaces (
  id uuid PRIMARY KEY, name text, timezone text, created_by uuid REFERENCES public.profiles(id)
);
CREATE TABLE public.movie_space_memberships (
  space_id uuid REFERENCES public.movie_spaces(id), user_id uuid REFERENCES public.profiles(id), role text,
  PRIMARY KEY (space_id, user_id)
);
CREATE TABLE public.movies (id uuid PRIMARY KEY, tmdb_id bigint, title text);
CREATE TABLE public.movie_space_watchlist (
  space_id uuid REFERENCES public.movie_spaces(id), movie_id uuid REFERENCES public.movies(id),
  added_by_user_id uuid REFERENCES public.profiles(id)
);
CREATE TABLE public.movie_nights (
  id uuid PRIMARY KEY, space_id uuid REFERENCES public.movie_spaces(id), schedule_mode text, scheduled_date date
);
CREATE TABLE public.movie_night_movies (
  night_id uuid REFERENCES public.movie_nights(id), movie_id uuid REFERENCES public.movies(id), position int
);
CREATE TABLE public.movie_space_watch_records (
  id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(), space_id uuid REFERENCES public.movie_spaces(id),
  movie_id uuid REFERENCES public.movies(id), watched_precision text, created_by_user_id uuid REFERENCES public.profiles(id)
);
CREATE TABLE public.movie_space_movie_ratings (
  space_id uuid REFERENCES public.movie_spaces(id), movie_id uuid REFERENCES public.movies(id),
  user_id uuid REFERENCES public.profiles(id), rating int
);
CREATE TABLE storage.buckets (id text PRIMARY KEY, name text, public boolean NOT NULL);
CREATE TABLE storage.objects (
  id uuid PRIMARY KEY, bucket_id text REFERENCES storage.buckets(id), name text, version text, metadata jsonb
);
CREATE TABLE public.profile_avatar_assets (
  id uuid PRIMARY KEY, user_id uuid REFERENCES public.profiles(id), source text,
  object_key text, delete_after timestamptz
);
CREATE TABLE public.profile_avatars (
  user_id uuid PRIMARY KEY REFERENCES public.profiles(id),
  custom_id uuid REFERENCES public.profile_avatar_assets(id), discord_id uuid REFERENCES public.profile_avatar_assets(id)
);
ALTER TABLE public.profile_avatar_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.movie_space_movie_ratings ENABLE ROW LEVEL SECURITY;
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT ON public.profile_avatar_assets TO anon;
GRANT SELECT ON public.movie_space_movie_ratings TO authenticated;
CREATE FUNCTION public.list_movie_space_movie_ratings(requested uuid)
RETURNS SETOF public.movie_space_movie_ratings LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  SELECT r.* FROM public.movie_space_movie_ratings r
  WHERE r.space_id = requested AND EXISTS (
    SELECT 1 FROM public.movie_space_memberships m
    WHERE m.space_id = requested AND m.user_id = current_setting('request.jwt.claim.sub', true)::uuid
  );
$$;
REVOKE ALL ON FUNCTION public.list_movie_space_movie_ratings(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_movie_space_movie_ratings(uuid) TO authenticated;
GRANT USAGE ON SCHEMA public, auth, storage, extensions, supabase_migrations TO postgres;
GRANT SELECT ON ALL TABLES IN SCHEMA public, auth, storage TO postgres;
