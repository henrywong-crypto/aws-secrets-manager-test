create table if not exists user_group_memberships (
    user_id    uuid        not null references users(user_id) on delete cascade,
    group_id   uuid        not null references groups(group_id) on delete restrict,
    created_at timestamptz not null default now(),

    primary key (user_id, group_id)
);

create index if not exists idx_ugm_group on user_group_memberships (group_id);
