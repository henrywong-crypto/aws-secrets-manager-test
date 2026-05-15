create table if not exists groups (
    group_id    uuid        primary key default uuid_generate_v4(),
    group_name  text        not null unique,
    description text,
    created_at  timestamptz not null default now()
);

insert into groups (group_name, description)
values ('portal-admins', 'May manage groups and prefix policies')
on conflict (group_name) do nothing;
