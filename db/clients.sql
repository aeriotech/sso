create table clients
(
	client_id char(128) not null
		constraint clients_pk
			primary key,
	client_name varchar not null,
	internal boolean default false not null,
	client_secret char(128) not null
);

comment on table clients is 'Client information';

create unique index clients_client_id_uindex
	on clients (client_id);

