# A1:2017 Injection

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 3 | Prevalence 2 : Detectability 3 | Technical 3 : Business |
| In pratica ogni sorgente di dati può essere una fonte di un attaco di tipo *injection*: variabili di ambiente, parametri, web services esterni ed interni e tutti i tipi di utenti. Una [Injection flaws](https://www.owasp.org/index.php/Injection_Flaws)si ha quando un attaccante può inviare dati dannosi ad un interprete. | Il codice legacy, è particolarmente esposto ai rischi di Injection flaws. Le vulnerabilità di tipo *injection* si trovano spesso in queries SQL, LDAP, XPath o NoSQL, in comandi OS, parsers XML, headers SMTP, expression languages (EL) e queries OML. Le *Injection flaws* sono facilmente individuabili analizzando il codice. L´uso di scanners and fuzzers può agevolare gli attaccanti ad individuare eventuali *injection flaws*. |Le *injection* possono causare perdita o corruzione dei dati, loro pubblicazione a entità non autorizzate, impossibilità di identificare i responsabli delle azioni, o nell´impedire l´accesso alle applicazioni. Una *Injection* in alcuni casi può condurre alla presa totale del controllo di un host. L´impatto sul business dipende dalla natura della applicazione e dei dati.|

## L'Applicazione è vulnerabile?

Una applicazione è vulnerabile all'attacco quando:

* I dati inseriti da utenti non sono validati, filtrati o sanati dalla applicazione.
* Queries dinamiche o chiamate non parametrizzate e prive di opportuno escaping, sono usate direttamente nell'interprete.  
* Dati ostili possono essere usati come parametri di ricerca in strutture ORM (object-relational mapping) per estrarre records aggiuntivi e sensibili.
* Dati ostili possono essere usati direttamente o mediante concatenazione all'interno di queries dinamiche, comandi o stored procedures.
* Alcuni dei più comuni tipi di *injections* si hanno in queries SQL, NoSQL, in comandi OS, Object Relational Mapping (ORM), LDAP, Expression Language (EL), Object Graph Navigation Library (OGNL). In concetto è lo stesso per ogni tipo di interprete. Il miglior modo per verificare se una applicazoine è vulnerabile ad attacchi di tipo *injection* è attraverso *source code review*, immediatamente seguito dall'uso di test automatici su tutti i dati di input siano essi parametri, headers, URL, cookies, JSON, SOAP, o XML. È possibile prevedere specicifici tools per eseguire test di tipo statico([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) e dinamico ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) nella pipeline di Continuos Integration e Continuos Delivery, al fine di identificare eventuali introduzioni di nuove falle di tipo *injection* prima del rilascio in produzione.

## How To Prevent

Preventing injection requires keeping data separate from commands and queries.

* The preferred option is to use a safe API, which avoids the use of the interpreter entirely or provides a parameterized interface, or migrate to use Object Relational Mapping Tools (ORMs). **Note**: Even when parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data, or executes hostile data with EXECUTE IMMEDIATE or exec().
* Use positive or "whitelist" server-side input validation. This is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications.
* For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter. **Note**: SQL structure such as table names, column names, and so on cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report-writing software.
* Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.

## Example Attack Scenarios

**Scenario #1**: An application uses untrusted data in the construction of the following vulnerable SQL call:

'String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";'

**Scenario #2**: Similarly, an application’s blind trust in frameworks may result in queries that are still vulnerable, (e.g. Hibernate Query Language (HQL)):

'Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");'
In both cases, the attacker modifies the ‘id’ parameter value in their browser to send:  ' or '1'='1. For example:

'http://example.com/app/accountView?id=' or '1'='1'

This changes the meaning of both queries to return all the records from the accounts table. More dangerous attacks could modify or delete data, or even invoke stored procedures.

## References

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### External

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
