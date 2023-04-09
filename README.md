Tema 1 - PROTOCOALE DE COMUNICARE
In aceasta tema am avut de implementat un router pentru comunicarea a mai multor host-uri. Host-urile pot trimite sau primi pachete de tip IPV4 sau ARP.

Proces:
Am inceput prin alocarea tabelei de rutare si tabelei a(goala pentru inceput). Dupa aceea am castat informatia din buffer la header-ul de tip eth pentru a verifica ce fel de informatie am primit. Exista 2 tipuri:

1. ARP(cu codul 0x0806)
    In acest caz trebuie verificat daca este Request sau Reply.     
        - Daca am primit Request inseamna ca cineva din retea are nevoie de adresa MAC a unui device conectat in retea. Fac rost de aceasta adresa MAC, completez tabela arp (daca nu exista deja aceasta legatura intre adresa IP si MAC) si trimit inapoi de unde a venit.
        - Daca am primit Reply inseamna ca s-a completat tabela ARP deci pot sa continui procesul. Se scoate din coada informatia(vezi IPV4) si se trimite la destinatarul dorit.
    
2. IPV4 (codul 0x0800)
    In acest caz trebuie intai verificata integritatea datelor prin recalcularea checksum-ului si comparat cu cel primit. In cazul in care checksum-ul este prost se ignora datele. Daca este bun, se scade ttl(time to live) si se salveaza noul checksum. Urmeaza trimiterea de date. Se verifica intai daca in tabela ARP exista o intrare cu ip-ul rutei dorite. Daca nu exista se salveaza intr-o coada datele si se genereaza un ARP Request. Daca exista se trimit datele catre destinatar.

3. ICMP
    Acesta se genereaza in urmatoarele 3 cazuri:
        - s-a primit un echo(tipul este 0)
        - nu s-a gasit ruta in tabela de rutare (tipul este 3)
        - ttl a ajuns sa fie 1 sau mai putin (tipul este 11)
    In toate cele 3 cazuri se reface header-ul de ethernet (cu adresele MAC interschimbate, trebuie trimis inapoi), se genereaza un nou header de tip IPV4 si se genereaza un header de tip ICMP. In final, in vectorul de date se vor afla urmatoarele date: ETH, IPV4, ICMP, IPV4_old(pentru codurile 3 si 11).
