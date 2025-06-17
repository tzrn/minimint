if [ -f db ]; then
    rm -i db
fi

sqlite3 db \
"CREATE TABLE user(
    id integer primary key autoincrement,
    name text NOT NULL,
    password text,
    status text,
    session text
);

CREATE TABLE post(
    id integer primary key autoincrement,
    parent_post_id integer,
    user_id integer,
    contents text,
    time integer
);

CREATE TABLE post_attachment(
    id integer primary key autoincrement,
    post integer,
    file integer
);

CREATE TABLE tag(
    id integer primary key autoincrement,
    name text
);

CREATE TABLE post_tag(
    id integer primary key autoincrement,
    post integer,
    tag integer
);

CREATE TABLE message(
    id integer primary key autoincrement,
    from_ integer,
    to_ integer,
    contents text,
    time integer
);

CREATE TABLE message_attachment(
    id integer primary key autoincrement,
    message integer,
    file integer
);

CREATE TABLE follow(
    id integer primary key autoincrement,
    follower integer,
    followee integer
);

CREATE TABLE file(
    id integer primary key autoincrement,
    public bool,
    time int,
    owner int,
    url text,
    name text,
    type text
);"
