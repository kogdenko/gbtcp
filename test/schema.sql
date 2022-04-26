CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE IF NOT EXISTS "journal" (id integer primary key autoincrement, test_id integer secondary key, status int, cps BLOB, ipps BLOB, ibps BLOB, opps BLOB, obps BLOB, concurrency BLOB);
CREATE TABLE IF NOT EXISTS "app" (id integer primary key autoincrement, name varchar(16), ver varchar(16), UNIQUE(name, ver));
CREATE TABLE IF NOT EXISTS "os" (id integer primary key autoincrement, name varchar(16), ver varchar(16), UNIQUE(name, ver));
CREATE TABLE cpu_model (id integer primary key autoincrement, name text secondary key, alias text secondary key, UNIQUE(name), UNIQUE(alias));
CREATE TABLE IF NOT EXISTS "test" (id integer primary key autoincrement, git_commit varchar(40), os_id int, app_id int, concurrency int, cpu_model_id int, cpu_count int, FOREIGN KEY(app_id) REFERENCES app(id), FOREIGN KEY(os_id) REFERENCES os(id), FOREIGN KEY(app_id) REFERENCES app(id), FOREIGN KEY(cpu_model_id) REFERENCES cpu_model(id), UNIQUE(git_commit, os_id, app_id, concurrency, cpu_model_id, cpu_count));
