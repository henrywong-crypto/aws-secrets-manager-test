create table if not exists users (
    user_id    uuid         primary key default uuid_generate_v4(),
    user_email varchar(255) not null unique,
    created_at timestamptz  not null default now()
);
