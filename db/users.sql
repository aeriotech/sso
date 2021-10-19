create table users
(
	id char(128) not null
		constraint users_pk
			primary key,
	username varchar not null,
	password varchar not null,
	salt char(32),
	email varchar
);

comment on table users is 'Contains user IDs associated with the username and password hash';

create unique index users_username_uindex
	on users (username);

create unique index users_id_uindex
	on users (id);

