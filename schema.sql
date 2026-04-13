DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS user_role;

CREATE TABLE users (
  id INTEGER,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  PRIMARY KEY (id) 
);

CREATE TABLE notes (
  id INTEGER,
  user_id INTEGER NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  PRIMARY KEY (id) ,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
/*
ho scelto di creare una tabella con i ruoli al posto di aggiungere
semplicemente un campo ruolo nella tabella users per poter gestire 
eventuali nuovi ruoli e permettere ad un utente di avere più ruoli 
contemporaneamente.
Inoltre ho dato per scontato che tutti gli utenti abbiano il ruolo 
"user"
*/

CREATE TABLE roles (
  id INTEGER,
  role TEXT NOT NULL UNIQUE,
  level INTEGER NOT NULL UNIQUE,
  PRIMARY KEY (id) 
);

CREATE TABLE user_role (
  user_id INTEGER,
  role_id INTEGER,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);
