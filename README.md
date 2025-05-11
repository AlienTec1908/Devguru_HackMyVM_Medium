# Devguru - HackMyVM (Medium)

![Devguru.png](Devguru.png)

## Übersicht

*   **VM:** Devguru
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Devguru)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 11. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Devguru_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Medium"-Challenge war es, Root-Zugriff auf der Maschine "Devguru" zu erlangen. Der Angriff begann mit der Entdeckung eines exponierten `.git`-Verzeichnisses auf dem Webserver (Apache, Port 80) und einer Gitea-Instanz (Port 8585). Durch das Dumpen des `.git`-Verzeichnisses wurde der Quellcode der Webanwendung (vermutlich OctoberCMS/WinterCMS) wiederhergestellt, wodurch Datenbank-Zugangsdaten (`october:SQ66...`) aus `config/database.php` offenbart wurden. Diese ermöglichten den Zugriff auf die Datenbank via `adminer.php`. Dort wurde der Bcrypt-Hash des CMS-Administrators `frank` durch einen eigenen, bekannten Hash ersetzt. Nach dem Login ins CMS-Backend wurde RCE durch Modifikation eines PHP-Templates erlangt, was eine Shell als `www-data` ermöglichte. Als `www-data` wurde ein Backup der Gitea-Konfigurationsdatei (`/var/backups/app.ini.bak`) mit Datenbank-Zugangsdaten (`gitea:UfFP...`) gefunden. Mit diesen wurde der PBKDF2-Hash des Gitea-Users `frank` aus der Gitea-Datenbank ausgelesen und durch einen eigenen ersetzt. Über einen manipulierten Git Hook (`post-receive`) in einem neu erstellten Gitea-Repository wurde eine Shell als Benutzer `frank` erlangt. Schließlich erlaubte eine `sudo`-Regel für `frank`, `sqlite3` als jeder Benutzer außer `root` auszuführen. Durch Angabe der User-ID `-1` (die oft als `root` interpretiert wird) konnte diese Einschränkung umgangen und eine Root-Shell erlangt werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `dirb`
*   `GitTools` (`gitdumper.sh`, `extractor.sh`)
*   `Adminer` (Web Interface)
*   `bcrypt-generator.com` (oder ähnliches Tool)
*   `curl`
*   `nc` (netcat)
*   `python3`
*   `linpeas.sh`
*   `mysql` (Client)
*   Go Playground (oder lokales Go)
*   `git`
*   `Gitea` (Web Interface)
*   `sudo` (auf Zielsystem)
*   `sqlite3` (als Exploit-Vektor)
*   Standard Linux-Befehle (`vi`, `stty`, `find`, `ps`, `cat`, `echo`, `ls`, `cd`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Devguru" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Git Repository Exploit:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.107`, Hostname `devguru.hmv`).
    *   `nmap`-Scan identifizierte SSH (22/tcp), Apache (80/tcp) mit einem exponierten `.git`-Verzeichnis und eine Gitea-Instanz (8585/tcp).
    *   `gobuster` fand auf Port 80 u.a. `/backend` (CMS-Admin-Login) und `/adminer.php`.
    *   Das `.git`-Verzeichnis wurde mit `gitdumper.sh` heruntergeladen und der Quellcode mit `extractor.sh` wiederhergestellt.
    *   In `config/database.php` wurden MySQL-Zugangsdaten (`october:SQ66EBYx4GT3byXH` für die Datenbank `octoberdb`) gefunden.

2.  **Database Access & CMS Takeover (Zugriff als `www-data`):**
    *   Mit den gefundenen Datenbank-Credentials wurde über `/adminer.php` auf die `octoberdb` zugegriffen.
    *   In der Tabelle `backend_users` wurde der Bcrypt-Hash des Admin-Benutzers `frank` gefunden.
    *   Ein eigenes Passwort (`Benni1908`) wurde mit Bcrypt gehasht und der alte Hash in der Datenbank überschrieben.
    *   Erfolgreicher Login in das CMS-Backend (`/backend`) als `frank` mit dem neuen Passwort.
    *   RCE wurde durch Modifikation eines PHP-Templates im CMS (Einfügen von `shell_exec($_GET['cmd'])`) erreicht.
    *   Eine Python3-Reverse-Shell wurde über den `cmd`-Parameter gestartet, was eine Shell als `www-data` ergab.

3.  **Privilege Escalation (von `www-data` zu `frank` via Gitea):**
    *   Als `www-data` fand `linpeas.sh` ein Backup der Gitea-Konfiguration (`/var/backups/app.ini.bak`).
    *   Darin befanden sich MySQL-Zugangsdaten für die Gitea-Datenbank (`gitea:UfFPTF8C8jjxVF2m`).
    *   Aus der Gitea-Datenbank (`gitea.user` Tabelle) wurden der PBKDF2-Hash und Salt des Gitea-Benutzers `frank` extrahiert.
    *   Ein neuer PBKDF2-Hash für ein bekanntes Passwort (`Benni1908`) wurde mit dem extrahierten Salt generiert und der alte Hash in der Datenbank überschrieben.
    *   Erfolgreicher Login in die Gitea-Weboberfläche (Port 8585) als `frank` mit dem neuen Passwort.
    *   Ein neues Gitea-Repository wurde erstellt und ein `post-receive` Git Hook mit einer Bash-Reverse-Shell-Payload konfiguriert.
    *   Durch einen Push in dieses Repository wurde der Hook ausgelöst und eine Shell als Benutzer `frank` erlangt.

4.  **Privilege Escalation (von `frank` zu `root` via Sudo/Sqlite3):**
    *   Als `frank` zeigte `sudo -l`, dass `/usr/bin/sqlite3` als jeder Benutzer außer `root` (`(ALL, !root) NOPASSWD: /usr/bin/sqlite3`) ausgeführt werden durfte.
    *   Diese Regel wurde umgangen, indem `sudo -u#-1 /usr/bin/sqlite3 /dev/null '.shell /bin/sh'` ausgeführt wurde. Die User-ID `-1` wird oft als `root` interpretiert.
    *   Dies startete eine Shell als `root`. Die User- und Root-Flags wurden gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Exponiertes `.git`-Verzeichnis:** Ermöglichte die Wiederherstellung des Quellcodes und das Auffinden von Datenbank-Credentials.
*   **Hartcodierte Credentials:** Datenbank-Passwörter in `config/database.php` und `app.ini.bak`.
*   **Vorhandensein von `adminer.php`:** Ermöglichte Datenbankzugriff und -manipulation.
*   **CMS-Template-Bearbeitung für RCE:** Administratoren konnten PHP-Code in Templates einfügen und ausführen.
*   **Gitea Git Hooks für RCE:** Ermöglichte die Ausführung von Shell-Befehlen als der Benutzer, unter dem Gitea lief (`frank`).
*   **Unsichere `sudo`-Regel (`sqlite3` mit `!root`-Umgehung):** Die spezifische `sudo`-Konfiguration erlaubte eine Umgehung der `!root`-Beschränkung durch Verwendung der User-ID `-1`.
*   **Klartext-Passwörter in Backups:** Das Gitea-Datenbankpasswort wurde in einer Backup-Datei gefunden.

## Flags

*   **User Flag (`/home/frank/user.txt`):** `22854d0aec6ba776f9d35bf7b0e00217`
*   **Root Flag (`/root/root.txt`):** `96440606fb88aa7497cde5a8e68daf8f`

## Tags

`HackMyVM`, `Devguru`, `Medium`, `Web`, `Apache`, `Git`, `GitTools`, `OctoberCMS`, `WinterCMS`, `Adminer`, `PHP RCE`, `Gitea`, `Git Hooks`, `MySQL`, `PBKDF2`, `sudo`, `sqlite3`, `Privilege Escalation`, `Linux`
