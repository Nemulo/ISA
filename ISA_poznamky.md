1. Prednaska
## Komunikacia klient server

klient - zariadenie/proces ktory komunikuje so serverom - vytvara rozhranie pre komunikaciu, zasiela poziadavky na server
Server - caka na poziadavky, obsluzi poziadavku a posle odpoved

V pripade ze server neodpovie:
1. Sluzba/server nebezi - pride sprava ## ICMP ## - informacia o tom aky je problem: timeout a pod.

Protokol - subor syntaktickych a semantickych pravidiel podla ktorych prebieha komunikacia medzi klientom a serverom
Popisuje vytvorenie spojenia, adresovanie, prenos dat, riadneie toku a zabezpecenie
Popisany gramatikou, Petriho sietou alebo stavovym automatom

Prostriedky pre komunikaciu: pipes/RPC/Sockety

Socket/schranka: API pre komunikujuce procesy -> koncovy komunikacny bod
Je to datova struktura resp. zaznam ktory obsahuje udaje pre komunikaciu
Identifikovana pomocou IP a portu
Vytvaraju rozhranie na L4(TCP/UDP)

Konkurenty server:
TCP:
Klient connect()
Server accept() - mame deskriptor procesu
Server fork() -> child is served
po tom ako je obsluzeny child je closed()

komunikacia TCP:
Klient                      Server
                            Socket()
                            Bind()
Socket()                    Listen()
                            Accept()
connect()  -----------------> |
        three way handshake   V
write() -------------------->Read()

Read() <--------------------Write()

Close()-------------------->Read()
                            Close()

Konkurenty UDP:
Podobne ako TCP, problem vsak nastava pri viacerych poziadavkach od klienta(nakolko UDP je bezstavovy),
UDP procesy o sebe navzajom nevedia,nevie rozlisit ktory UDP datagram patri ku ktoremu toku, riesenie je prejst na TCP komunikaciu alebo pomocou fork je procesu prideleny novy port( sluzba TFTP)
pri TFTP je problem NAT alebo firewall

Pri dns sa cely poziadavok posiela v jednom pakete, ak sa nezmesti, prejde sa na TCP

Shared UDP sockets:
client                  Server
socket()                Socket()
                        Bind()
sendto()                recvfrom()
recvrom()               sendto()
close()

nevyhnutna funkcia je implementacia Timeout
pri zahodeni sa vygeneruje ICMP sprava

na zachytavanie ICMP sprav sa pri udp pouziva funkcia connect() -> nevytvara spojenie TCP

## Unicast
komunikacia 1 k 1
zistime podla IP adresy 
Vytvorenie Paketu ->
        pridelenie source:  IP -> prideli nas pocitac
                            port -> prideli nas pocitac
                            mac -> prideli sietova karta nasho pocitaca
        pridelenie dest:    IP -> na zaklade DNS resolucie
                            Port -> bud poznam alebo prideli aplikacia
                            Mac -> na zaklade arp zaznamu (IPv4), ND(IPv6)-> neigh discovery

Adresy : IPv4 -> triedy A, B ,C
        IPv6 -> prefix 2000 /3

TCP moze prebiehat iba pri unicaste 

## BroadCast
komunikacia one to all
vseobecny: 255.255.255.255
sietovy -> iba host id: host.host.255.255
Vytvorenie paketu:
            source: port -> prideleny OS
                    adresa -> pridelena zdrojovym zariadenym
                    zdrojova MAC -> sietove rozhranie zariadenia

            dest port-> pozname
                 adresa -> vsetky(broadcast adresa)
                 MAC -> FFFFFFFFFFF

ICMP sa negeneruju!!
Priklad broadcast DHCP, vyhladavanie zdrojov ARP, NTP
funguje iba pre UDP
Broadcastova domena je obmedzena na L3 podsiet (napriklad router)

2. prednaska 
Nazvy datovych jednotiek

L7  app layer (data)
L4  transport layer (segment/packet)
L3  network layer (Ip datagram)
L2 datalink layer (Frame)
L1 physical layer (Bit)  

adresovanie na L2 vrstve:
Adresovanie sietovej karty(NIC):
48-bit fyzicka adresa -> jednoznacne identifikuje sietove rozhranie pocitaca
urcene k adresovaniu v lokalnej sieti
24  bit        :       24 bit
OUI                     cislo sietoveho rozhrania pridelene vyrobcom
L2 ramec obsahuje typ protokolu:
0x0800 IPv4/0x086DD IPv6

Broadcast: ff:ff:ff:ff:ff:ff
multicast IPv4: 01:00:5E:xx:xx:xx
multicast IPv6: 33:33:xx:xx:xx:xx

Adresovanie na L3 vrstve:
IPv4/ IPv6
adresa jednoznacne identifikuje sietove rozhranie pocitaca V SIETI
adresovanie aj mimo lokalnej siete
IPv4 = netID+hostID
adresovanie s vyuzitim tried:
A -> prefix 8
B -> prefix 16
C -> prefix 24
D -> multicast  (224-239)
E -> experimenty
beztriedne adresovanie (variabilna dlzka masky)
subneting: Netid|subnetID|hostID

Pridelovanie adries pomocou DHCP
Dynamicka konfiguracia IPv4 pomocou BOOTP alebo DHCPv4
Dynamicka konf. IPv6: typ konfiguracie sa urci podla priznakov (M-> managed, O-> other)

Adresovanie na L4:
pomocou cisla portu (16 bit)
jednoznacne identifikuje sluzbu na danom pocitaci(spojovana TCP alebo nespojovana UDP)

Adresovanie na L7:
zavisi na konkretnej aplikacii napr Elektronicka posta,DNS,WWW ...

## DHCP
Dynamic Host Configuration Protocol (DHCP) je súbor zásad, ktoré využívajú komunikačné zariadenia (počítač, router alebo sieťový adaptér), umožňujúci zariadeniu vyžiadať si a získať IP adresu od servera, ktorý má zoznam adries voľných na použitie.

DHCP Server (Dynamic Host Configuration Protocol) vykonáva automatické pridelenie IP adries svojim klientom. Môžu to byť akékoľvek systémy, podporujúce DHCP. DHCP je štandardný protokol, môžu ho využívať aj systémy mimo Microsoft. Z Microsoft operačných systémov podporujú funkciu DHCP klienta všetky až na veľmi exotický LAN Manager pre OS / 2.V rámci siete potom máme DHCP Server - prideľujúci adresy a počítače - ktoré ich od neho preberajú (DHCP Clients). V sieti môžu byť aj počítače, ktoré majú tieto adresy nastavené manuálne.


3. Pr  naska
Bezpecnost
Bezpecnostne rizika:
Man in the middle, Malware, podvr sprav, DoS, Falsovanie Identity

Poziadavky su:
Doveryhodnost -> spravy/ data ktore su smerovane mne dostanem iba ja
Autentizacia -> viem sa preukazat ze som to ja 
Integrita dat -> data niesu pozmenene po ceste
Dostupnost -> serveru napriklad, ake su tam prava kto ich moze vyuzivat

### Kryptografia ###
Nauka o utajovani sprav, zaistenie autentizacie integrity a dovernosti

Symetricka a asymetricka kryptografia
Symetricka - rovnake kluce, ja zasifrujem svojim, druhy odsifruje tym istym
Asymetricka - Verejny a sukromny kluc

sifrovanie - integrita
Casto symetricka kryptografia (kryptograficky hash) - pouziva sa zdielany tajny kluc pre vytvorenie a overenie hashu

Elektronicky podpis - asymetricka kryptografia, odosielatel podpise vlastnym sukromnym, prijmatel overi verejnym klucom

Symetricke blokove sifry DES,3DES,AES,IDEA
proudove symetricke sifry DES,RC4,SEAL

vyhoda symetrickeho sifrovania - Rychlost
nevyhoda - distribucia klucov, rozsiritelnost

Nastroje openssl enc
Algoritmy Base64

Vyuzitie SSL,IPSec

Asymetricke :
integrita, doveryhodnost
Algoritmy RSA,DSA, DH

Vyhoda : lahka rozsiritelnost
Nevyhoda : pomale, problem s overenim verejneho kluca

Nastroje openssl genpkey, pkeyutl, rsa

# kryptograf hash (HMAC)
Integrita dat MD4/SHA ...

princip sprava+kluc, to sa zasifruje, pripoji sa hash  
Pouzitie pri DNSSEC, SSL...

problem s distribuciou klucov

# elektronicky podpis
Asymetricka kryptografia, podpisujeme suboroy(software, aktualizacie a pod.),Dokumenty,Email
Overenie pravosti

Princip:
Odosielatel si vygeneruje kluce, zo spravy vytvori hash, hash zasifruje klucom pripoji k sprave
Prijmatel si zoberie verejny kluc odsifruje hash, hash porovna

pouzitie v TLS,IPSec

kluce sa ukladaju v PKI(public key infrastructure), spravovane certifikacnymi autoritami(CA)
CA generuje, podpisuje, uklada a overuje certifikaty k verejnym klucom(Elektronickym podpisom)
CA vytvara vazby kluca k realnym osobam

Problem s overenim CA ? -> CA musi byt niekym overena (rootvskej CA)

# Digitalny certifikat
Dokument overujuci pravost verenjeho kluca a prislusnost k danemu uzivatelovi
Vydavany certifikacnou autoritou, overenie podpisu CA sa vykonava korenovou CA
Protokol OCSP sa pouziva na overenie certifikatu

Certifikat (forma X500) obsahuje:
seriove cislo
Identifikaciu uzivatela Distinguised name
Datum platnosti
Identifikaciu vydavatela
ucel verejneho kluca
verejny kluc 
pouzity algoritmus

# algoritmus Diffie-Hellman(DH)
funguje na principe umocnovani cisel
Princip:
Uzly A a B sa dohodnu na modulu[m] = 10 a zaklade[z] = 4
A si zvoli tajne cislo [a] = 7, posle x=Z^a mod m = [4]
B si zvoli tajne cislo [b] = 4, posle y=Z^b mod m = [6]
A urci kluc k =y^a mod m = [6]
B spocita kluc k = x^b mod m = [6]

pouzitie IPSec SSL/TLS

# zabezpecenie v praxi
L7 -> DNSSEC,PGP, S/MIME
L4 -> SSL/TLS
L3 -> IPSec VPN
L2 -> VPN PPTP
L1 -> WPA

problem nastava -> sifrovanie je iba do najblizsieho access pointu 

# TLS
komunikuje nad L4, zabezpecuje prenos dat protokolov aplikacnej vrstvy, zaistuje dovernost, integritu, autentizaciu
pouzitie HTTPs, SMTPs,POPs,IMAP4s

Vytvorenie spojenia TLS
Client hello
Server hello+certificate,server key exchange
Client certificate, client key exchange, certificate verify

zabezpecenie -> sifrovanie: generovanie tajneho klucu, vymena pomocou RSA alebo DH
            -> autentizacia pomocou certifikatov
            -> integrita pomocou hashu(kryptografickeho)

Obmedzenia: vyzadu7je overeny certifikat serveru
            nezaistuje autentizaciu uzivatela
            problem pri monitorovania

# IPSec
skupina protokolov(ramec) ktory obsahuje protokoly AH,ESP
funguju v tunelovaciom a transportnom rezime
Transportny - zachova sa dany paket a prida sa iba AH A ESP
Tunelovaci - vezme sa datagram, zaobali sa do noveho datagramu kde sa pridaju Ah a ESP

AH -> chrani integritu pomocou HMAC
    -> v transportnom rezime prida do packetu AH a prida tuto hlavicku,
    -> v tunelovacom prida AH do payloadu a zabali do noveho packetu

ESP: zajistuje autentizaciu dovernost a integritu
    -> v Trasportnom rezime pridava ESP hlavicku
    -> v tunelovacom paket zabalime do ESP a posiela sa

# Pretty Good Privacy (PGP)
princip:
odosielatel vypocita hash spravy, vezme svoj privatny kluc a vytvori digitalny podpis, cela sprava sa sifruje symetrickou sifrou ktoru odosielatel vygeneruje
verejnym klucom prijemcu zasifruje kluc, prpoji ho k sprave a posle to prijemcovi

# OSPF
zapuzdreny v IP
typ autentizacie : ziadny, jednoduchy pass, kryptograficke

4. prednaska

# DNS #######
Globalny adresar nazvov pocitacov a dalsich identifikatorov sietovych zariadeni a sluzieb
funguje formou domenoveho stromu: mapovanie domenovych mien na IP adresy
DNS protokol funguje pomocou prenosu zon a rezolucie
Usporiadanie
            ""(korenovy uzol DNS)
    com     cz      sk      org         (domeny 1. urovne)
    //spravovane nardonymi registratormi/ genericke domeny
google      vutbr       facebook        (domeny 2. urovne)
    // spravovane jednotlivymi uzivatelmi/instituciami
        fit     stud                    (uzivatelske domeny)
        //spravovane spravcom domeny

Domena je cast podstromu v systeme(hierarchii) domenoveho stromu
Domenove meno je cesta od uzlu ku korenu

vyhladavanie zacina od korena

vyhladanie IP v domenovom strome sa riesi pomocou reverznych zaznamov -> invertovany strom(domena arpa)
Sprava dns -> ICANN
Sprava IP adries -> Ip adresy prideluju registratori(RIR/LIR) 
                -> spravuje ich IANA
                -> vyhladanie vlastnika pomocou whois

Domenove servery spravuju len casti priestoru domenovych mien - zony
Typy serverov DNS:
1. Primarny -> obsahuje uplne a autoritativne zaznamy o domenach ktore spravuje
2. sekundarny -> uchovava autoritativne kopie dat od primarnych serverov
3. zalozne(cachovacie) -> ukladaju si odpovede od primarnych a sekundarnych serverov(autoritativynch)

Zistenie ktory server je primarny pomocou SOA zaznamu
zistenie ktory server je autoritativny pomocou NS zaznamu 
komunikacia prebieha pomocou UDP protokolu

2 typy komunikacie
1. Rezolucia 
2. prenos zon -> ak sekundarnemu expiruju nejake zaznamy tak si poziada od primarneho na aktualizaciu

vyhladavanie zacina bud manualne alebo cez DHCP -> ziskame lokalny primarny alebo sekundarny server
1. Rezolucia proces vyhladania odpovede v systeme DNS
    vzdy zacina od korenoveho seerveru
    Rekurzivne alebo iterativne
    Rekurzivny hlada odpoved kym ju nenajde
    Iterativny posle najlepsiu moznu odpoved -> bud odpoved ktoru hladame alebo server kde sa odpoved moze nachadzat

na zistenie kde sa nachadza korenovy server sa pouziva zona 'hint'
Typy prenosu zon -> inkrementalny alebo celkovy
Format DNS zaznamu
[meno(domena)]     [TTL]   [trieda]    [Typ]   [Rdata(konkretne_meno)]
email.fit.vutbr.cz  14400   IN           CNAME  nemo.fit.vutbr.cz 

kazda zona ma soa zaznam ktory obsahuje
nazov primarneho serveru a email spravca
seriove cislo
refresh interval 
retry interval
expire
priklad:
####    
fit.vutbr.cz 144000 IN SOA guta.fit.vutbr.cz    \\ primarny dns server
                    michal.fit.vutbr.cz         \\ mail na spravcu
                    20312031203                 \\ serial
                    10800                       \\ refresh
                    3600                        \\ retry
                    12312341                    \\ expire
                    3232                        \\ minimum

Ip adresy obsahuju typ A(IPv4)/AAAA(IPv6)

MX zaznam -  sluzi na spravne dorucenie elektronickej posty -> presmeruje postu pre danu domenu na korektny postovy server, moze obsahovat viac serverov s roznou prioritou

CNAME zaznam mapuje alias na kanonicke meno
email.fit.vutbr.cz  14400   IN           CNAME  nemo.fit.vutbr.cz 
mapuje email... na nemo...

PTR zaznam mapuje IPv4 a IPv6 na domenovu adresu -> obsahuje reverzne mapovanie
29.23.123.1.in-addr.arpa 1500 IN PTR www.fit.vutbr.cz

SRV zaznam sluzi na lokalizaciu sluzieb a serverov napriklad SIP XMPP
_sip._udp.cesnet.cz 130 IN SRV 100 ... cyrus.cesnet.cz
[toto]      bezi na serveri             [tu]

# zabezpecenie systemu DNS
Utoky : podvrh dns zaznamu, cache poisoning - vkladanie nespravnych odpovedi do cache DNS serverov
        DoS -> obrana pomocou vacsej vykonnosti sluzby/ odfiltrovanie nelegitimneho provozu

DNSSEC -> rozsirenie DNS od podpisovanie zaznamov
Pouzivaju sa 2 typy klucov ZSK(zone signing key) na podpisovanie zon
a KSK(key singnig key) na podpisovanie klucov

Definuju sa nove zaznamy -> DNSKEY: verejny kluc
                            RRSIG: podpis daneho zaznamu
                            NSEC: odkaz na dalsi zaznam
                            DS: zaznam pre overenie zaznamu DNSKEY ulozeny v nadradenej domene

Princip podpisovania:
podpisovanie zon: privatym klucom uklada sa do RRSIG zaznamu
                    verejnym klucom ulozenym do DNSKEY pouziva sa na overenie RRSIG

Podpisovanie klucov: verejny kluc sa ulozi v DS zazname na overenie DNSKEY
                        Privatnym sa podpisuje DNSKEY zaznam

ochrana sukromia dotazovania na DNS:
pomocou sifrovania dotazov DoT(DNS over TLS) a DoH(DNS over HTTPS)
1. DoT sifruje dotaz DNS ktory je viditelny iba vybranemu DNS serveru
2. DoH predkonfigurovane v prehliadaci

5. Prednaska 
## Elektronicka posta
Klient musi mat prvy SMTP server nastaveny
Zistenie Postoveho servera pomocou MX zaznamu 
Pomocou SMTP serverov prebieha zasielanie sprav, Na stiahnutie spravy klientom sa pouziva POP3 alebo IMAP

format emailovej domeny : xnemet@stud.fit.vutbr.cz -> stud.. je domena emailoveho serveru -> zistenie emailoveho serveru podla MX zaznamu
Smerovanie sprav podla DNS

Moze to byt napojene na adresarovu sluzbu(vyhladavanie vramci organizacie ucastnikov) -> LDAP
Princip odosielania posty:
postovy klient Mail User Agent
postovy server Mail Transfer Agent

7-bitove kodovanie moze byt upravovane (v pripade pisania diakritikou) = quoted-printable
Base64 znaky sa koduju zase do normalne tisknutelnych - 6 bitov

SMTP -> Aplikacny protokol nad TCP na porte 25
Definuje format prikazov a odpovedi

POP3 ->
        iba jeden klient na scranku at time
        obsah preneseny az po ukonceni prace
IMAP -> viacnasobny pristup
        viac schranok, praca s hlavickami
        moznost atributov(videne, odpovedane, recent...)

# zapezpecenie mailu
PGP 
Sprava je podpisana sukromnym klucom odosielatela
sprava je zasifrovana verejnym tajnym klucom prijemcu -> kvoli rychlosti symetricke
kluc je zasifrovany verejnym klucom prijemcu

SPF ->
        umoznuje vlastnikovi dns domeny deklarovat, ktore servery su opravnene odosielat emailove spravy podla domeny
        -> specifikacie v DNS TXT
Princip:
        v zazname popiseme napriklad ze posta fit.vutbr.cz moze chodit iba z konkretnej ip
        sprava kam email prichadza sa pozrie do zaznamov a zisti ze sprava s domenou fit.vutbr.cz moze chodit iba z IP nejakeho rozsahu
DKIM ->
        zabezpecenie obsahu pred zmenou pomocou elektronickeho podpisu, ALE moze to vykonat ktorykovek clanok insfrastruktury
        nachadza sa v DNS TXT zazname
        Validuju sa napriklad hlavicky subject to from ...

DMARC -> vyuziva aj SPF aj DKIM -> definuje podmienky jak overit odosielatela a to co sa stane s mailom ak mail neodpoveda tymto podmienkam, kam sa hlasia problemy

# adresarove sluzby
Elektronicka databaza pre vyhladavanie uzivatelov/ overovanie udajov, povodne navrhnute ako podpore elektronickej posty
LDAP -> aplikacny protokol nad TCP
Architektura : information model:
                        popisuje typy dat a atributov
                naming model:
                        organizacia a prepajanie dat
                Funkcionalny model:
                        ako sa k datam pristupuje, vyhladavanie
                Security model:
                        zabezpecenie
Vyuziva directory tree
Zaznam je popisany triedou objektov napr. person, obsahuje zoznam atributov, a jednoznacny ID distinguished name DN
obsah moze byt kodovany base64
model je organizovany pomocou Directory Tree smerovanie pomocou referrals, zaznamy typu alias
Operacie napriklad modify bind unbind, add...
Vyuzite na autentizaciu: Web, unixove prihlasenie pre konkretnych uzivatelov

6. Prednaska
### Hlasove sluzby
architektura klasickej siete :
Koncove stanice -> ustredna pripojena k najblizsiemu switchu, tie spolu komunikuju
kontrolna signalizacia -> zavesebe, zdvihnute, ringing
Adresova signalizacia
Informacna signalizacia -> busy,nezname cislo
Vyhody:
        garantovana sirka pasma
        dobra kvalita
        spolahlivost
        napajane priamo z ustredny

poziadavky ba IP telefonie:
        dostatocne prenosove pasmo, kvalita, spolahlivost,bezpecnost, integracia do verenej PTSN

Architektura: 
Prevod hlasu na IP Datagram
riadenie komunikacie - cez ustrednu(gatekeeper) alebo peer-to-peer
        registracia
        adresovanie
        smerovanie
        vytbaranie hovorov
gateway(brana)
Aplikacne sluzby DHCP,DNS,LDAP
Signalizacne protokoly SIP
# SIP
Aplikacny protokol nad UDP a je urceny na signalizaciu VoIP
        registracia
        naviazanie hovoru
        adresovanie pomocou sipURI sip:user@domain
nezaistuju kvalitu ani prenos
Pomocou NAPTR sa da najst ktory server spravuje aku domenu cez DNS zaznam
smerovacie informacie su v SIP hlavicke Via, Route -> naviazanie spojenia
Problem spojenia s NATom = ukladame si privatne hlavicky ktore si nevie ukladat da sa to nastavit aby si to vedel prelozit

dolezita je registracia -> 
uklada polohu klienta do lokalizacnej databaze
SIP klient posle svoju IP adresu a port SIP serveru na svojej domene
metoda INVITE obsahuje PDU protokolu SDP

SDP - prenasa informacie ohladom koncoveho zariadenia napriklad codecy a dalsie informacie

RTP - pouziva sa na streamy... prenasa hlasove a vizualne data
Maju sekvencne cisla kvoli prehratia
RTCP kontrolny protokol

NAPTR zaznam je reverzny zaznam prekladu domeny na sluzbu a kde sa ma pytat na SRV zaznamy

Zabezpecenie VoIP
rizika:
        odpocuvanie
        virusy
        DoS
        neautorizovane pouzitie sluzby

Zabezpecenia:
IPSec, Secure RTP VLAN
7. Prednaska
Sprava sieti

Monitorovanie, sledovanie zatazenia, bezpecnost, zalohovanie

SNMP -> Sledujeme stav monitorovanych objektov

system pre spravu siete musi zajistovat:
        viditelnost siete, SNMP logy, NetFlow

        aktivne/pasivne monitorovanie
        zber dat/metadat

        spracovanie dat:
                ukladanie, filtrovanie, agregacia korelacia udalosti

        odozva na udalosti

ICMP ->
        ohlasenie nedostupnosti siete(pri zahodeni paketu), IBA UNICAST
IGMP -> prihlasovanie do IPv4 multicast skupiny

ICMPv6 ->
        MLD prihlasovanie a odhlasovanie sa z multicastovych skupin
        RS/RA - Posle spravu ze sa pyta a zisti si kto je DHCP server v sieti/ alebo router
        NS/NA - mapuje si pomocou toho siet - pyta sa susedov na IP adresy a smerovanie na Mac adresu

SNMP ->
        Managament station : zistuje si z objektov informacie
        Zakladne prvky: Monitorovane objekty, popisane pomocou SMI
                                Adresovonia pomocou OID(object identifier)
                        Usporiadanie objektov do skupin MIB
                                stromova struktura
                        System monitorovania NMS, SNMP agent
                        Prenosovy protokol SNMP
                                pouziva prikazy Get Set Trap GetNext

                        SMI Pakety/Objekty sa koduju pomocou BER

        jazyk SMI definuje pravidla pre vytvaranie monitorovanych objektov:
                objekt ma nazov nejaky vyznam a nejaky datovy TYP pre ucely monitorovania

        Protokol SNMP aplikacny protokol pre pracu s monitorovanymi objektami , bezstavovy protokol
8. prednaska
# NetFlow
Monitorovanie sietoveho toku
Loguju sa metadata o kazdom pakete

Pouzitie statistickych dat:
        identifikacia napadnutych pocitacov
        Sledovanie uniku dat
        Vytvaranie profilov(bezna pracovna doba/neaktivita)

Analyza provozu -
        sledovanie obsahu paketov DPI
        vyladavanie znamych retazcov ->
                detekcia malware/ DoS
                filtrovanie komunikacie

Tok - je postupnost paketov (zaznam po komunikacii) prechadzajuci bodom ktory je pozorovany
Architektura :
        Exporter(smerovac/dedikovane zariadenie) -> generuje/ziskava statistkiky o tokoch napr. nprobe
        Prenos pomocoui Protokolu NetFlow
        Kolektor -> zariadenie ktore uklada zaznamy z exporteru

Proces monitorovania:
        vygenerovany paket pride na smerovac/sondu
        Vytvori sa zaznam vo flow cache
        ak pride odpoved serveru, vytvori sa dalsi zaznam
        Zaznamy obsahuju zdojova cielova adresa, port, pocet paketov, bytov
        vygenerovani noveho paketu sa iba aktualizuju statistiku sietoveho toku

        Tok je vzdy jeden smer

        zaznam si moze ukladat aj protokoly,sluzby, flagy a podobne

Netflow protokol pracuje na UDP principe

pri TCP sa flow da zistit ukoncenim (FIN/RST)
pri UDP zistime koniec podla Inactive Timeoutom(vseobecne u vsetkych protokolov ktore neukoncuju komunikaciu jednoznacne)

Po vyprsani Active timeoutu na exporteri sa informacie automaticky exportuju
Po expiraci timeoutov/ukoncenia komunikacie moze exportu predchadzat agregacia ale ta prebieha vacsinou na kolektore

Sampling pri exporteri:
pre znizenie narokov na hardware
moze byt pouzite pri kolektore aj pri exporteri
Deterministicky sampling(pravidelne vzorkovanie)
Nahodny sampling(nahodne vzorkovanie v casovom okne)

Kolektor:
        prijma pakety NetFlow z exporterov
        spracovanie, agregacia dat

NetFlow pouziva pre popis sturktur sablony ktore obsahuju dalsie informacie
9. Prednaska
# Quality of service
kvalita nad L3(IP vrstva) ->
        markovanie paketov do skupin Podla hlavicky TypeofService
        Service level agreement - popisuje to co provider zaistuje(dostupnost, povolena stratovost...)

        Regulacia provozu
                traffic shaping, policing
                shaping:
                        riesi problem zhlukov, lepsie vyuziva pasmo ale vnasa zpozdeni do siete
                        od providera ide vacsinou shaping
                        a smerom ku klientovi/od klienta ide policing
        Prioritizacia provozu, zaistenie kvality prenosu
                rezervacia prenosoveho pasma RSVP

Prakticke zaistenie QoS :
        prioritizacia spracovania paketov vo vstupnych frontach(iba ak linky nezvladaju)

Fronty FIFO, Priority Q, Round Robit(v kazdom cykle sa odoberie zo vsethych front), vahove fronty(RR spolu s mnostevnou prioritou -> pocet paketov odobranych z fronty)

riadenie rychlosti -> Leaky Bucket pouziva shaping
                Token bucket -> generujeme "zetony" ktore povoluju prenosu paketov s velkostou zetonu
                                -> CIR -> priemerna rychlost
                                -> peak rate

                                rychlost prenostu zavisi od rychlosti generovania tokenov a maximalneho poctu paketov

Integrovane sluzby(IntServ)
 -> implementuju QoS v IP sieti formov rezervacie sietovych zdrojov
        -> RSVP protokol posle poziadavok po ceste ktoru si chcem rezervovat

vlastnosti a vyuzitie:
        alokacia zrojov na toky, maly pocet sluzieb

diferenciovane sluzby DiffServ - 
        klasifikuju pakety,maju prioritne preposielanie

RED a WRED 
 -> prevencia zahltenia
        regulovanie rychlosti posielania paketov na linku
        RED -> preventivne zahadzovanie paketov na zakladne nahodnej pravdepodobnosti v zavislosti od plnosti frony
        Weighted RED -> vyuzitie prioritizacie zahadzovania paketov(niektory provoz zahadzujem skor)
