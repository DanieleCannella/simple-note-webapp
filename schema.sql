CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT,
  username VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  PRIMARY KEY (id) 
);

CREATE TABLE IF NOT EXISTS notes (
  id INT AUTO_INCREMENT,
  user_id INT NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  title VARCHAR(255) NOT NULL,
  body TEXT NOT NULL,
  PRIMARY KEY (id),
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

CREATE TABLE IF NOT EXISTS roles (
  id INT AUTO_INCREMENT,
  role VARCHAR(100) NOT NULL UNIQUE,
  level INT NOT NULL UNIQUE,
  PRIMARY KEY (id) 
);

CREATE TABLE IF NOT EXISTS user_role (
  user_id INT,
  role_id INT,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);