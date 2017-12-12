# A1:2017 Injection

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 3 | Prevalence 2 : Detectability 3 | Technical 3 : Business |
| In pratica ogni sorgente di dati può essere una fonte di un attaco di tipo *injection*: variabili di ambiente, parametri, web services esterni ed interni e tutti i tipi di utenti. Una [Injection flaws](https://www.owasp.org/index.php/Injection_Flaws)si ha quando un attaccante può inviare dati dannosi ad un interprete. | Il codice legacy, è particolarmente esposto ai rischi di Injection flaws. Le vulnerabilità di tipo *injection* si trovano spesso in queries SQL, LDAP, XPath o NoSQL, in comandi OS, parsers XML, headers SMTP, expression languages (EL) e queries OML. Le *Injection flaws* sono facilmente individuabili analizzando il codice. L’uso di scanners and fuzzers può agevolare gli attaccanti ad individuare eventuali *injection flaws*. |Le *injection* possono causare perdita o corruzione dei dati, loro pubblicazione a entità non autorizzate, impossibilità di identificare i responsabli delle azioni, o nell’impedire l’accesso alle applicazioni. Una *Injection* in alcuni casi può condurre alla presa totale del controllo di un host. L’impatto sul business dipende dalla natura della applicazione e dei dati.|

## L'Applicazione è vulnerabile?

Una applicazione è vulnerabile all'attacco quando:

* I dati inseriti dagli utenti non sono validati, filtrati o sanati dall’applicazione.
* Queries dinamiche o chiamate non parametrizzate e prive di opportuno escaping, sono usate direttamente dall'interprete.  
* Dati ostili possono essere usati come parametri di ricerca in strutture ORM (object-relational mapping) per estrarre records aggiuntivi e sensibili.
* Dati ostili possono essere usati direttamente o mediante concatenazione all'interno di queries dinamiche, comandi o stored procedures.
* Alcuni dei più comuni tipi di *injections* si hanno in queries SQL, NoSQL, in comandi OS, Object Relational Mapping (ORM), LDAP, Expression Language (EL), Object Graph Navigation Library (OGNL). Il concetto è lo stesso per ogni tipo di interprete. Il miglior modo per verificare se una applicazoine è vulnerabile ad attacchi di tipo *injection* è attraverso una *source code review*, immediatamente seguito dall'uso di test automatici su tutti i dati di input, siano essi parametri, headers, URL, cookies, JSON, SOAP, o XML. È possibile prevedere specicifici tools per eseguire test di tipo statico([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) e dinamico ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) nella pipeline di Continuos Integration e Continuos Delivery, al fine di identificare eventuali introduzioni di nuove falle di tipo *injection* prima del rilascio in produzione.

## Prevenzione

Per prevenire attacchi di tipo *injection* occorre mantenere separati i dati dagli script di comando e dalle queries.
 
* L’opzione da preferire consiste nel far uso di API sicure, che non facciano alcun uso dell’interprete o che forniscano interfacce parametriche, oppure ricorrere all’uso di strumenti ORM (Object Relational Mapping). **Nota**: Anche se parametrizzate, le stored procedures possono ancora introdurre *injection SQL* se in PL/SQL o T-SQL si concatena queries e dati, o si eseguono dati ostili con EXECUTE IMMEDIATE o exec().
* Fare uso di "whitelist" o validazione degli input di tipo positivo lato server. Questa non è una difesa completa in quanto molte applicazioni fanno uso di caratteri speciali, come in aree di testo o APIs per applicazioni mobile.
* Per le queries dinamiche rimanenti, occore eseguire l’escape dei caratteri speciali usando la sintassi di escape specifica per l’interprete. **Nota**: su strutture SQL come nomi di tabella, nomi di colonne e simili, non si può eseguire l’escape, quindi nomi di strutture fornite dagli utenti risultano sempre pericolose. Questo è un problema comune nel software per la generazione di reportistica.
* Fare uso di LIMIT ed altri controlli SQL all’interno delle queries per impedire l’estrazione massiva di records in caso di *SQL injection*.

## Scenari esempio di attacco

**Scenario #1**: Una applicazione usa dati non sicuri nella costruzione delle seguenti chiamate SQL:

'String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";'

**Scenario #2**: Analogamente, una assoluta fiducia nei frameworks può portare a queries vulnerabili, (ad es. Hibernate Query Language (HQL)):

'Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");'
In entrambi i casi, l’attaccante modifica il valore del parametro ‘id’ sul proprio browser per inviare *' or '1'='1*. Ad esempio:

'http://example.com/app/accountView?id=' or '1'='1'

Ciò cambia il significato di entrambe le queries e fa restituire tutti i records della tabella *accounts*. Attacchi più pericolosi possono modificare o cancellare i dati, o addirittura invocare stored procedures.
## Riferimenti

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### Esterno

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
