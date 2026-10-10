-- Shelf: books and daily reading logs, one set per Telegram user.
-- RLS is on with no policies: the browser never talks to these tables directly.
-- All access goes through the shelf-api Edge Function, which checks Telegram initData
-- and uses the service role key.

create table if not exists public.books (
  id             uuid primary key default gen_random_uuid(),
  tg_user_id     bigint not null,
  title          text not null,
  authors        text not null default '',
  cover          text not null default '',
  cover_color    text,
  status         text not null default 'want'
                 check (status in ('want', 'reading', 'finished', 'not_finished')),
  progress_pages integer not null default 0 check (progress_pages >= 0),
  total_pages    integer check (total_pages > 0),
  volume_id      text,
  added_at       timestamptz not null default now()
);
create index if not exists books_user_added_idx on public.books (tg_user_id, added_at desc);

create table if not exists public.reading_logs (
  tg_user_id bigint not null,
  day        date not null,
  amount     integer not null check (amount >= 0),
  unit       text not null check (unit in ('pages', 'time')),
  primary key (tg_user_id, day)
);

alter table public.books enable row level security;
alter table public.reading_logs enable row level security;
