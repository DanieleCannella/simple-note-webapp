*Choose your language / Scegli la lingua:*

* [🇬🇧 English](#english-version)  
* [🇮🇹 Italiano](#versione-italiana)

# **English Version**

# **Simple Note Webapp**

Simple Note Webapp is a web application developed in Python with the Flask framework, designed for the secure and intuitive management of personal notes. The project is fully containerized using Docker and relies on MySQL for data persistence and Redis for efficient user session management.

## **✨ Features**

* **Secure Authentication:** Registration and login system implemented with password hashing via bcrypt and automatically generated salts.  
* **Role-Based Access Control (RBAC):** Hierarchical permission management via distinct roles (User, Moderator, Admin) to restrict access to administrative features.  
* **Note Management (CRUD):** Comprehensive interface to create, read, update, and delete personal notes.  
* **Sorting and Pagination:** Ability to sort notes by title, creation date, or last modified date, with an integrated pagination system to handle a large number of items.  
* **Staff Dashboard:** Dedicated administration area for user management (creating new accounts, deleting, and modifying roles).  
* **Advanced Session Management:** Server-side sessions stored in Redis (via Flask-Session), with support for configurable timeouts and a persistent "Remember Me" feature.  
* **CSRF Protection:** All state-changing modules (forms) are protected from Cross-Site Request Forgery attacks using Flask-WTF tokens.  
* **Database Connection Pooling:** Optimized management of MySQL connections to prevent bottlenecks under heavy load.  
* **Structured Logging:** Integrated logging system with configurable detail levels (e.g., DEBUG, INFO) to facilitate monitoring and troubleshooting.  
* **Simplified Deployment with Docker:** Easily reproducible development and production environments thanks to Docker Compose, featuring service health checks and volumes for data persistence.

## **🛡️ Security Features**

| Feature | Implementation |
| :---- | :---- |
| **Password Hashing** | Uses bcrypt to securely hash passwords before storing them. |
| **Session Management** | Server-side sessions backed by Redis via Flask-Session, keeping sensitive session data off the client. Configurable TTL included. |
| **CSRF Protection** | Flask-WTF generates and validates tokens on all state-changing requests (POST, PUT, DELETE), mitigating Cross-Site Request Forgery. |
| **Timing Attack Prevention** | Computes a dummy hash during login even if the username is not found, thwarting user enumeration based on response times. |
| **SQL Injection Prevention** | Strict usage of parameterized queries through the MySQL driver prevents malicious SQL code injection. |
| **Session Timeout** | Automatically logs the user out after a defined period of inactivity, configurable via environment variables. |
| **Connection Pooling** | Maintains a pool of reusable database connections to prevent resource exhaustion during traffic spikes. |

## **🛠️ Technology Stack**

* **Backend:** Python 3.11, Flask, Flask-Session, Flask-WTF  
* **Database:** MySQL 8.0 (with mysql.connector.pooling)  
* **Cache & Sessions:** Redis 7  
* **Frontend:** HTML/Jinja2, custom CSS, Vanilla JavaScript, Bootstrap 5  
* **Infrastructure:** Docker, Docker Compose

## **⚙️ Environment Variables**

Before starting the project, the environment must be configured by creating an .env file in the root directory. You can start with the provided .env.example file in the repository.  
⚠️ **Security Note:** The placeholder values shown below (especially the passwords and the DEBUG logging level) are strictly intended for local development and testing. **Always use strong, unique passwords and an appropriate logging level (e.g., INFO or WARNING) in a production environment.**

| Variable | Description | Example Value (from .env.example) |
| :---- | :---- | :---- |
| SECRET\_KEY | Secret key for Flask and CSRF token signing. | *(Generate a secure, random alphanumeric string)* |
| DB\_NAME, DB\_USER, DB\_PASS | Basic configuration for MySQL access. | simple\_note\_db, db\_user, your\_password |
| DB\_ROOT\_PASS | Password for the MySQL root user (required for Docker). | your\_root\_password |
| DB\_HOST | Database hostname (db if running in Docker, localhost if running locally). | db |
| DB\_POOL\_NAME, DB\_POOL\_SIZE | Name and size of the MySQL connection pool. | simple\_note\_pool, 5 |
| REDIS\_PASS, REDIS\_URL | Password and full URL for connecting to the Redis server. | redis://:your\_redis\_pwd@redis:6379/0 (if in Docker) |
| LOGGING\_LEVEL | Logging verbosity level. | DEBUG *(Use INFO in production)* |
| SESSION\_TIMEOUT\_MINUTES | Minutes of inactivity before the standard session expires. | 5 |
| SESSION\_TIMEOUT\_REMEMBER\_ME\_DAYS | Days the session remains valid if "Remember Me" is selected. | 30 |

## **🚀 Setup and Launch with Docker (Recommended)**

Using Docker and Docker Compose is the quickest way to test and deploy the application, as it automatically manages the MySQL and Redis dependencies.

### **Prerequisites**

* [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed on your system.

### **Procedure**

1. **Copy the configuration file:**  
   cp .env.example .env  
   *Ensure that DB\_HOST is set to db (the service name in docker-compose).*  
2. **Build and start the containers:**  
   Run the following command in the root directory:  
   docker-compose up \-d \--build  
   Docker will download the images, build the Flask application, and start all services in the background. On the first launch, the web container will automatically run the init\_db.py script, which will configure the database schema and create the initial administrator account.

## **💻 Setup in a Local Environment (Without Docker)**

If you prefer to run the application natively without containers, follow these steps:

### **Prerequisites**

* **Python 3.11+**  
* An active **MySQL** server running locally.  
* An active **Redis** server running locally.

### **Procedure**

1. **Set up the virtual environment and install dependencies:**  
   python \-m venv venv  
   source venv/bin/activate  \# On Windows use: venv\\Scripts\\activate  
   pip install \-r requirements.txt  
2. **Prepare the environment variables:**  
   Copy .env.example to .env. Set DB\_HOST=localhost and ensure that the MySQL credentials and the Redis URL match your local configuration.  
3. **Initialize the Database:**  
   Run the initial configuration script to create tables and roles:  
   python init\_db.py  
4. **Start the Flask application:**  
   flask \--app simple\_note\_webapp.py run \--host=0.0.0.0

## **🌐 Using the Application**

The application is divided into two main areas: the user area for notes and the administration dashboard.

### **Default Administrator Account**

During the initial database setup (performed by init\_db.py), the following global administration account is created automatically. You can use it to access both sections immediately:

* **Username:** Admin  
* **Password:** admin

### **1\. User Area (Personal Notes)**

* **URL:** http://localhost:5000/login  
* **Description:** The main interface where users can manage (create, read, modify, delete) their personal notes.  
* **New Users:** You do not need to use the Admin account to test the app. By clicking **"Registrati"** (or navigating to http://localhost:5000/register), you can create a standard account (User) in seconds to save your own notes.

### **2\. Staff Dashboard (Administration Panel)**

* **URL:** http://localhost:5000/staff/login  
* **Description:** A protected area accessible only to users with elevated privileges (Moderator, Admin). It allows you to view the list of registered users, add new accounts directly from the panel, change assigned roles, or delete specific accounts.

# **Versione Italiana**

# **Simple Note Webapp**

Simple Note Webapp è un'applicazione web sviluppata in Python con il framework Flask, progettata per la gestione sicura e intuitiva di annotazioni personali. Il progetto è completamente containerizzato tramite Docker e si affida a MySQL per la persistenza dei dati e a Redis per una gestione efficiente delle sessioni utente.

## **✨ Funzionalità**

* **Autenticazione Sicura:** Sistema di registrazione e login implementato con l'hashing delle password tramite bcrypt e salt generato automaticamente.  
* **Controllo degli Accessi Basato sui Ruoli (RBAC):** Gestione gerarchica dei permessi tramite ruoli distinti (User, Moderator, Admin) per limitare l'accesso alle funzionalità amministrative.  
* **Gestione delle Note (CRUD):** Interfaccia completa per creare, leggere, aggiornare ed eliminare le proprie annotazioni.  
* **Ordinamento e Paginazione:** Possibilità di ordinare le note per titolo, data di creazione o ultima modifica, con un sistema di paginazione integrato per gestire un elevato numero di elementi.  
* **Dashboard Staff:** Area di amministrazione dedicata per la gestione degli utenti (creazione di nuovi account, eliminazione e modifica dei ruoli).  
* **Gestione Avanzata delle Sessioni:** Sessioni lato server memorizzate su Redis (tramite Flask-Session), con supporto per timeout configurabile e funzionalità "Ricordami" persistente.  
* **Protezione CSRF:** Tutti i moduli (form) che alterano lo stato dell'applicazione sono protetti da attacchi Cross-Site Request Forgery utilizzando i token di Flask-WTF.  
* **Database Connection Pooling:** Gestione ottimizzata delle connessioni a MySQL per prevenire colli di bottiglia sotto carico.  
* **Logging Strutturato:** Sistema di log integrato con livelli di dettaglio configurabili (es. DEBUG, INFO) per facilitare il monitoraggio e il troubleshooting.  
* **Deploy Semplificato con Docker:** Ambiente di sviluppo e produzione facilmente riproducibile grazie a Docker Compose, con health check per i servizi e volumi per la persistenza dei dati.

## **🛡️ Sicurezza**

### **Caratteristiche di Sicurezza**

| Funzionalità | Implementazione |
| :---- | :---- |
| **Hashing delle Password** | Utilizzo di bcrypt per salvare le password in modo sicuro, impedendone la lettura in chiaro. |
| **Gestione delle Sessioni** | Sessioni lato server salvate su Redis tramite Flask-Session, garantendo che i dati di sessione non risiedano sul client. Include un TTL (Time To Live) configurabile. |
| **Protezione CSRF** | I token generati da Flask-WTF vengono validati ad ogni richiesta POST, PUT o DELETE, bloccando le richieste malevole provenienti da siti di terze parti. |
| **Prevenzione Timing Attack** | Durante il login, viene eseguito il calcolo di un hash fittizio anche se l'username non esiste, evitando che un attaccante possa indovinare gli username validi misurando i tempi di risposta. |
| **Prevenzione SQL Injection** | Tutte le query al database utilizzano parametri associati (parameterized queries) offerti dal driver MySQL, bloccando l'iniezione di codice SQL. |
| **Timeout di Sessione** | Logout forzato dell'utente dopo un periodo predefinito di inattività, configurabile tramite variabili d'ambiente. |
| **Connection Pooling** | Mantiene un pool di connessioni riutilizzabili al database, evitando che l'applicazione esaurisca le risorse creando connessioni continue in momenti di picco. |

## **🛠️ Stack Tecnologico**

* **Backend:** Python 3.11, Flask, Flask-Session, Flask-WTF  
* **Database:** MySQL 8.0 (con mysql.connector.pooling)  
* **Cache & Sessioni:** Redis 7  
* **Frontend:** HTML/Jinja2, CSS custom, Vanilla JavaScript, Bootstrap 5  
* **Infrastruttura:** Docker, Docker Compose

## **⚙️ Variabili d'Ambiente**

Prima di avviare il progetto, è necessario configurare l'ambiente creando un file .env nella directory principale. Puoi partire dal file di esempio .env.example fornito nel repository.  
⚠️ **Nota di Sicurezza:** I valori mostrati di seguito (specialmente le password e il livello di log DEBUG) sono da intendersi esclusivamente come segnaposto per lo sviluppo locale e il test. **Utilizza sempre password sicure e univoche e un livello di log appropriato (es. INFO o WARNING) in un ambiente di produzione reale.**

| Variabile | Descrizione | Valore di Esempio (da .env.example) |
| :---- | :---- | :---- |
| SECRET\_KEY | Chiave segreta per Flask e la firma dei token CSRF. | *(Genera una stringa alfanumerica sicura e casuale)* |
| DB\_NAME, DB\_USER, DB\_PASS | Configurazione base per l'accesso a MySQL. | simple\_note\_db, db\_user, tua\_password |
| DB\_ROOT\_PASS | Password per l'utente root di MySQL (necessaria per Docker). | tua\_password\_root |
| DB\_HOST | Hostname del database (db se esegui in Docker, localhost se in locale). | db |
| DB\_POOL\_NAME, DB\_POOL\_SIZE | Nome e dimensione del pool di connessioni a MySQL. | simple\_note\_pool, 5 |
| REDIS\_PASS, REDIS\_URL | Password e URL completo per la connessione al server Redis. | redis://:tua\_pwd\_redis@redis:6379/0 (se in Docker) |
| LOGGING\_LEVEL | Livello verbosità dei log. | DEBUG *(Usa INFO in produzione)* |
| SESSION\_TIMEOUT\_MINUTES | Minuti di inattività prima della scadenza della sessione standard. | 5 |
| SESSION\_TIMEOUT\_REMEMBER\_ME\_DAYS | Giorni di validità della sessione se viene selezionato "Ricordami". | 30 |

## **🚀 Setup e Avvio con Docker (Raccomandato)**

L'utilizzo di Docker e Docker Compose è il modo più rapido per testare e distribuire l'applicazione, poiché gestisce automaticamente le dipendenze di MySQL e Redis.

### **Prerequisiti**

* [Docker](https://docs.docker.com/get-docker/) e [Docker Compose](https://docs.docker.com/compose/install/) installati sul sistema.

### **Procedura**

1. **Copia il file di configurazione:**  
   cp .env.example .env  
   *Assicurati che DB\_HOST sia impostato su db (il nome del servizio su docker-compose).*  
2. **Costruisci e avvia i container:**  
   Esegui il seguente comando nella directory principale:  
   docker-compose up \-d \--build  
   Docker scaricherà le immagini, costruirà l'applicazione Flask e avvierà tutti i servizi in background. Al primo avvio, il container web eseguirà automaticamente lo script init\_db.py, che configurerà lo schema del database e creerà l'account amministratore iniziale.

## **💻 Setup in Ambiente Locale (Senza Docker)**

Se preferisci eseguire l'applicazione nativamente senza container, segui questi passaggi:

### **Prerequisiti**

* **Python 3.11+**  
* Un server **MySQL** attivo in locale.  
* Un server **Redis** attivo in locale.

### **Procedura**

1. **Configura l'ambiente virtuale e installa le dipendenze:**  
   python \-m venv venv  
   source venv/bin/activate  \# Su Windows usa: venv\\Scripts\\activate  
   pip install \-r requirements.txt  
2. **Prepara le variabili d'ambiente:**  
   Copia .env.example in .env. Imposta DB\_HOST=localhost e assicurati che le credenziali di MySQL e l'URL di Redis corrispondano alla tua configurazione locale.  
3. **Inizializza il Database:**  
   Esegui lo script di configurazione iniziale per creare tabelle e ruoli:  
   python init\_db.py  
4. **Avvia l'applicazione Flask:**  
   flask \--app simple\_note\_webapp.py run \--host=0.0.0.0

## **🌐 Utilizzo dell'Applicazione**

L'applicazione è suddivisa in due aree principali: l'area utenti per le note e la dashboard di amministrazione.

### **Account Amministratore Predefinito**

Durante la prima inizializzazione del database (eseguita da init\_db.py), viene creato automaticamente il seguente account di amministrazione globale. Puoi utilizzarlo per accedere subito a entrambe le sezioni:

* **Username:** Admin  
* **Password:** admin

### **1\. Area Utenti (Note Personali)**

* **URL:** http://localhost:5000/login  
* **Descrizione:** L'interfaccia principale dove gli utenti possono gestire (creare, leggere, modificare, eliminare) le proprie note personali.  
* **Nuovi Utenti:** Non è necessario utilizzare l'account Admin per provare l'app. Cliccando su **"Registrati"** (o navigando su http://localhost:5000/register), puoi creare in pochi secondi un nuovo account standard (User) per salvare le tue annotazioni.

### **2\. Dashboard Staff (Pannello Amministrativo)**

* **URL:** http://localhost:5000/staff/login  
* **Descrizione:** Un'area protetta accessibile solo agli utenti con privilegi elevati (Moderator, Admin). Permette di visualizzare l'elenco degli utenti registrati, aggiungere nuovi account direttamente dal pannello, modificare i ruoli assegnati o eliminare utenze specifiche.