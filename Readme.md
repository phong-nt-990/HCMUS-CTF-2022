# HCMUS-CTF WRITE-UP 2022

# [d4rkarmi.phongnt](https://ctf2022.hcmus.edu.vn/users/100) HCMUS-CTF-2022 Write-up

## 1. BabyDroid - Reverse Engineering

### Thông tin ban đầu:

Đầu tiên, dùng Bluestack install và chạy file Babydroid.apk, ta thấy màn hình hiển thị như sau:

![Untitled](https://scontent.xx.fbcdn.net/v/t1.15752-9/279918566_1046289449315833_3054018982793514126_n.png?_nc_cat=111&ccb=1-6&_nc_sid=ae9488&_nc_ohc=XRNdEMeLrjYAX_t0mng&_nc_ht=scontent.fhan3-3.fna&oh=03_AVLBciLplNGEaVG44w0qw5v9EBIr69iuyFjLvtRkiTEBZw&oe=62A7145E&_nc_fr=fhan3c03)

ta có thể thấy được babydroid nhận giá trị input, sau đó kiểm tra với điều kiện nào đó để trả về True hoặc False.

### Phân tích file babydroid.apk

- Ta dùng dex2jar để chuyển .apk file thành .jar file.

```bash
.\d2j-dex2jar.bat .\babydroid.apk
```

và dùng Jadx để đọc file babydroid.jar sau khi convert:

![Untitled](https://scontent.fhan3-4.fna.fbcdn.net/v/t1.15752-9/278413728_384470993608769_6138274731599703683_n.png?_nc_cat=104&ccb=1-6&_nc_sid=ae9488&_nc_ohc=ZtW1eNvZPxIAX-ztDvV&_nc_ht=scontent.fhan3-4.fna&oh=03_AVI5HLCqYLpmokUhQhDVQvioQ6EHZOFTHUu4E_TEty1b3Q&oe=62A9CF1F)

- Nhìn vào thư mục “com”, ta có rất nhiều điều thú vị ở đây

```java
├───example
│   └───babydroid
│           BuildConfig.class
│           FlagValidator.class
│           Helper.class
│           MagicNum.class
│           MainActivity$1.class
│           MainActivity$2.class
│           MainActivity.class
│           R$color.class
│           R$drawable.class
│           R$id.class
│           R$layout.class
│           R$mipmap.class
│           R$string.class
│           R$style.class
│           R.class
```

 

File “FlagValidator.class” có nhiệm vụ kiểm tra input có đúng hay không

```java
package com.example.babydroid;

import android.content.Context;

/* loaded from: classes3.dex */
public class FlagValidator {
    public static boolean checkFlag(Context ctx, String flag) {
        String result = Helper.retriever();
        if (flag.startsWith("HCMUS-CTF{") && flag.charAt(19) == '_' && flag.length() == 37 && flag.toLowerCase().substring(10).startsWith("this_is_") && flag.charAt(((int) (MagicNum.obtainY() * Math.pow(MagicNum.obtainX(), MagicNum.obtainY()))) + 2) == flag.charAt(((int) Math.pow(Math.pow(2.0d, 2.0d), 2.0d)) + 3) && new StringBuilder(flag).reverse().toString().toLowerCase().substring(1).startsWith(ctx.getString(R.string.last_part)) && new StringBuilder(flag).reverse().toString().charAt(0) == '}' && Helper.ran(flag.toUpperCase().substring((MagicNum.obtainY() * MagicNum.obtainX() * MagicNum.obtainY()) + 2, (int) (Math.pow(MagicNum.obtainZ(), MagicNum.obtainX()) + 1.0d))).equals("ERNYYL") && flag.toLowerCase().charAt(18) == 'a' && flag.charAt(18) == flag.charAt(28) && flag.toUpperCase().charAt(27) == flag.toUpperCase().charAt(28) + 1) {
            return flag.substring(10, flag.length() - 1).matches(result);
        }
        return false;
    }
}
```

Rất rối phải không :)), ta có thể đơn giản hoá code như sau:

```java

(flag.startsWith("HCMUS-CTF{")
&& flag.charAt(19) == '_'
&& flag.length() == 37 
&& flag.toLowerCase().substring(10).startsWith("this_is_") 

&& flag.charAt(((int) (MagicNum.obtainY()*Math.pow(MagicNum.obtainX(), MagicNum.obtainY()))) + 2) == flag.charAt(((int) Math.pow(Math.pow(2.0d, 2.0d), 2.0d)) + 3) 
// This line is: charAt(3 * (2^3) + 2) == charAt((2^2)^2 + 3) => charAt(26) == charAt(19) == '_'

&& new StringBuilder(flag).reverse().toString().toLowerCase().substring(1).startsWith(ctx.getString(R.string.last_part)) 
&& new StringBuilder(flag).reverse().toString().charAt(0) == '}' 

&& Helper.ran(flag.toUpperCase().substring((MagicNum.obtainY() * MagicNum.obtainX() * MagicNum.obtainY()) + 2, (int) (Math.pow(MagicNum.obtainZ(), MagicNum.obtainX()) + 1.0d))).equals("ERNYYL") 
// ...subtring(10, 26)

&& flag.toLowerCase().charAt(18) == 'a' 

&& flag.charAt(18) == flag.charAt(28) 
// == 'a'

&& flag.toUpperCase().charAt(27) == flag.toUpperCase().charAt(28) + 1
// == 'b'
```

Input là flag chính xác khi tất cả điều kiện trên trả về True

Phân tích:

- Flag có dạng HCMUS-CTF{this_is_}
- Các giá trị `MagicNum.obtainX()`, `MagicNum.obtainY()`, `MagicNum.obtainZ()` là các hằng số là 2, 3, 5 theo thứ tự được lấy từ hàm MagicNum được khai báo như sau:
    
    ```java
    package com.example.babydroid;
    
    /* loaded from: classes3.dex */
    public class MagicNum {
        public static int obtainX() {c
            return 2;
        }
    
        public static int obtainY() {
            return 3;
        }
    
        public static int obtainZ() {
            return 5;
        }
    }
    ```
    
    - ctx.getString(R.string.last_part) trả về string từ resources.arsc:
    
    ```java
    ...
    <string name="last_part">ver_cis</string>
    ...
    ```
    
    ⇒ string: “ver_cis” (string đã bị reverse)
    
    - Ta phân tích hàm ran:
    
    ```java
    public static String ran(String s) {
            String out = "";
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c >= 'a' && c <= 'm') {
                    c = (char) (c + '\r');
                } else if (c >= 'A' && c <= 'M') {
                    c = (char) (c + '\r');
                } else if (c >= 'n' && c <= 'z') {
                    c = (char) (c - '\r');
                } else if (c >= 'N' && c <= 'Z') {
                    c = (char) (c - '\r');
                }
                out = out + c;
            }
            return out;
        }
    ```
    
    với ‘\r’ == 13 trong bảng ASCII, nên qua code ta biết được hàm ran là thuật toán mã hoá Caecar (Caecar Cipher) với giá trị Shift = 13, giải mã đoạn "ERNYYL", ta được string “REALLY”
    
    Từ các dữ kiện trên do đó, chuỗi cần tìm có dạng:
    
    ![Untitled](https://scontent.xx.fbcdn.net/v/t1.15752-9/279238432_580459513308530_6632557414971671519_n.png?_nc_cat=110&ccb=1-6&_nc_sid=ae9488&_nc_ohc=Xsukbq6UQukAX9xX2B3&_nc_ht=scontent.fhan3-5.fna&oh=03_AVIScEIwYiWm5uIU2MjrOfiO98S3b3D3fDExQu_TBpFLHQ&oe=62A6FD64&_nc_fr=fhan3c05)
    
    Nhưng đó chưa phải kết thúc =)), sau khi nhiều lần submit Flag báo lỗi, ta quay lại hàm FlagValidator 1 lần nữa và biết được hàm FlagValidator chỉ kiểm tra chuỗi với “this_is_a_really_basic_rev” là viết thường, sau đó hàm trả về string đã được matches với hàm `result = Helper.retriever()` nên chuỗi HCMUS-CTF{string} chính là flag cần tìm
    
    Xem qua hàm Helper.retriever(), ta có như sau:
    
    ```java
    public static String retriever() {
            String str;
            StringBuilder sb;
            String r = "";
            boolean upper = true;
            for (int i = 0; i < 26; i++) {
                if (upper) {
                    sb = new StringBuilder();
                    sb.append(r);
                    str = "[A-Z_]";
                } else {
                    sb = new StringBuilder();
                    sb.append(r);
                    str = "[a-z_]";
                }
                sb.append(str);
                r = sb.toString();
                upper = !upper;
            }
            return r;
        }
    ```
    
    Theo code bên trên, ta có 1 vòng for với `upper =!upper`sau mỗi vòng lặp, ta đoán được hàm này dùng để convert string thành string khác có dạng hoa thường xen kẽ.
    
    Áp dụng vào chuỗi “this_is_a_really_basic_rev” và submit 2 trường hợp
    

### ⇒ Flag: `HCMUS-CTF{ThIs_iS_A_ReAlLy_bAsIc_rEv}`

## 2. Awareness - Forensics

### Thông tin ban đầu:

Sử dụng wireshark để mở file và thông tin cung cấp từ đề thi, flag có thể nằm trong các packet hoặc Objects nào đó.

### Phân tích file captured.pcapng

Đọc qua các packet trong file log, ta thấy có 2 địa chỉ ip đáng ngờ là 192.168.1.8 và 192.168.1.7. Packet đầu tiên được gửi bởi 192.168.1.8 ⇒ 192.168.1.7 với nội dung “Hello”. Ta bắt đầu phân tích tại điểm này:

- Dùng chức năng sort, ta sẽ bắt đầu xem qua 2 địa chỉ này giao tiếp với nhau như thế nào.

```
192.168.1.8 22.10: Hello
192.168.1.7 33.186: Hi! What do you want?
192.168.1.8 47.18: Can you give me the antivirus software?
192.168.1.7 68.5: Sure, you know the link, right?
192.168.1.8 75.705: I see it
192.168.1.8 133.67: I got it! Goodbye
192.168.1.7 139.14: See u then =D
```

- Chú ý rằng, sau đoạn hội thoại “Sure, you know the link, right?”, tại thời điểm 113,6s 192.168.1.8 đã gửi lệnh GET /malfinder đến 192.168.1.7 bằng giao thức HTTP, file này có thể là “antivirus” mà đề bài đã nhắc tới. Ta Export Objects malfinder đó thu được file có header như sau:

```
00000000  fd 37 7a 58 5a 00 00 04  e6 d6 b4 46 02 00 21 01  |.7zXZ......F..!.|
00000010  16 00 00 00 74 2f e5 a3  01 ed 4e fd 37 7a 58 5a  |....t/....N.7zXZ|
00000020  00 00 04 e6 d6 b4 46 02  00 21 01 16 00 00 00 74  |......F..!.....t|
00000030  2f e5 a3 01 ed 36 50 4b  03 04 14 00 00 00 08 00  |/....6PK........|
00000040  49 60 a8 54 43 47 22 c4  b2 9c 04 00 80 9c 04 00  |I`.TCG".........|
00000050  09 00 1c 00 6d 61 6c 66  69 6e 64 65 72 55 54 09  |....malfinderUT.|
00000060  00 03 d9 4e 77 62 d9 4e  77 62 75 78 0b 00 01 04  |...Nwb.Nwbux....|
00000070  00 00 00 00 04 00 00 00  00 00 43 80 bc 7f fd 37  |..........C....7|
00000080  7a 58 5a 00 00 04 e6 d6  b4 46 02 00 21 01 16 00  |zXZ......F..!...|
00000090  00 00 74 2f e5 a3 01 ec  e7 50 4b 03 04 14 00 00  |..t/.....PK.....|
...
```

- Từ đoạn header trên, đoán ra được file dạng nén .xz. Dùng công cụ bsdtar để giải nén file xz:

```
┌──(maple㉿kali)-[~/Desktop]
└─$ bsdtar xvf malfinder.xz
x malfinder
```

Chuyện gì đang xảy ra? Ta thấy sau khi giải nén file malfinder.xz thu được malfinder ?? Thật kỳ lạ. Từ file output tiếp tục giải nén lần 2 lần 3 kết quả thu được:

```
┌──(maple㉿kali)-[~/Desktop]
└─$ bsdtar xvf malfinder.xz                                                                                                                     130 ⨯
x malfinder
                                                                                                                                                      
┌──(maple㉿kali)-[~/Desktop]
└─$ bsdtar xvf malfinder.xz
x malfinder
```

Whut? Rename 3 file thành malfinder.xz1, malfinder.xz2, malfinder.xz3. Có vẻ như sau khi giải nén thì dung lượng file đã giảm xuống 1 ít

```
-rw-r--r-- 1 maple maple    302572 May 16 09:07  malfinder.xz1
-rw-r--r-- 1 maple maple    302208 May  8 01:02  malfinder.xz2
-rw-r--r-- 1 maple maple    301916 May  8 01:02  malfinder.xz3
```

Ohh, vậy có khi nào sau n lần giải nén thì ta thu được gì đó không? Thử code 1 đoạn bash như sau:

```bash
for i in {1..500}
do
	bsdtar xvf malfinder.xz   
	rm malfinder.xz
	mv malfinder malfinder.xz
done
```

Chạy đoạn bash, quá trình giải nén ngừng lại khi đến lần thứ 239, ta thử lại với đoạn bash mới như sau:

```bash
for i in {1..239}
do
	bsdtar xvf malfinder.xz   
	rm malfinder.xz
	mv malfinder malfinder.xz
done
```

Vẫn có gì đó không đúng, kết quả thu được vẫn là 1 file nén xz nhưng bsdtar không extract được? Thử copy file xz sang windows và dùng winRAR giải nén tiếp 2 lần (đoán xem tại sao lại được??), cuối cùng ta thu được file malfinder có header như sau:

```
00000000  25 50 44 46 2d 31 2e 33  0a 25 ba df ac e0 0a 33  |%PDF-1.3.%.....3|
00000010  20 30 20 6f 62 6a 0a 3c  3c 2f 54 79 70 65 20 2f  | 0 obj.<</Type /|
00000020  50 61 67 65 0a 2f 50 61  72 65 6e 74 20 31 20 30  |Page./Parent 1 0|
00000030  20 52 0a 2f 52 65 73 6f  75 72 63 65 73 20 32 20  | R./Resources 2 |
00000040  30 20 52 0a 2f 4d 65 64  69 61 42 6f 78 20 5b 30  |0 R./MediaBox [0|
00000050  20 30 20 35 39 35 2e 32  37 39 39 39 39 39 39 39  | 0 595.279999999|
00000060  39 39 39 39 37 32 37 20  38 34 31 2e 38 38 39 39  |9999727 841.8899|
00000070  39 39 39 39 39 39 39 39  39 38 36 34 5d 0a 2f 41  |999999999864]./A|
00000080  6e 6e 6f 74 73 20 5b 0a  3c 3c 2f 54 79 70 65 20  |nnots [.<</Type |
...
```

⇒ Đây là 1 file PDF. Mở file với Acrobat Pro, file chứa 1 đoạn javasript như sau:

```jsx
//<ACRO_source>Annot1:Page Exit:Action:1</ACRO_source>
//<ACRO_script>
/*********** belongs to: Multimedia:Annot1:Page Exit:Action:1 ***********/
    var _0x2258=["You have been hacked","alert","fromCharCode","submitForm","e69db","bd580","252a5","34550","b0a98","507d9","a4ee8","c8609","goodjob","amazing","unstoppable","legendary"];app[_0x2258[1]](_0x2258[0]);this[_0x2258[3]](String[_0x2258[2]](106,52,118,52,53,99,114,49,112,55));a1__1a= _0x2258[4];a__a__a= _0x2258[5];b1as= _0x2258[6];a2__2a= _0x2258[7];a3__3a= _0x2258[8];a4__4a= _0x2258[9];a5__5a= _0x2258[10];a6__6a= _0x2258[11];this[_0x2258[3]](a1__1a+ a__a__a+ b1as+ a2__2a+ a3__3a+ a4__4a+ a5__5a+ a6__6a);you= _0x2258[12];are= _0x2258[13];the= _0x2258[14];best= _0x2258[15]
    // axios.post(/fake-flag, {
    //     note: "be-careful",
    //     fflag: "HCM-US{W4rn1n55555}"
    // });
    // let you = "flag_for_fakeee";
    // if (you === "pass")
    
//</ACRO_script>
//</Multimedia>
```

Phân tích đoạn mã trên, ta thấy javascript được thực thi khi có Action: Page Exit, khi đó nó trả về 2 string như sau:

```jsx
j4v45cr1p7
e69dbbd580252a534550b0a98507d9a4ee8c8609
```

Thử với string1 nhưng báo lỗi, ta xem xét đến string2. d4rkarmi_thiph giải thích đó là thuật toán mã hoá SHA1. Dùng [hashtoolkit.com](http://hashtoolkit.com) để decrypt.

### ⇒ FLAG: `HCMUS-CTF{j4v45cr1p7_5up3r_bull5h17}`

## 3. SuperSecret - Misc

### Thông tin ban đầu

Từ thông tin đã cho từ đề thi, ta biết được Flag sẽ được 1 trong số các Mod leak. Sau 1 thời gian bị Richroll từ tác giả của đề thi này, theo bản năng nhận thấy tất cả file ảnh up lên channel đều rất đáng nghi. Thử tải về tất cả file ảnh ⇒ Flag chính là tên của file ảnh được gửi vào channel General

![https://scontent.fhan4-3.fna.fbcdn.net/v/t1.15752-9/280085705_711169370095462_7006821471890051629_n.png?_nc_cat=100&ccb=1-6&_nc_sid=ae9488&_nc_ohc=-AOioRPsxNsAX--Y56K&tn=L4jvcTJ-sL4LoJsG&_nc_ht=scontent.fhan4-3.fna&oh=03_AVJsqxqBtiXJZVKcNhZYy_beXNgNnK0nf3GIBSS9okPgCA&oe=62A9AF53](https://scontent.fhan4-3.fna.fbcdn.net/v/t1.15752-9/280085705_711169370095462_7006821471890051629_n.png?_nc_cat=100&ccb=1-6&_nc_sid=ae9488&_nc_ohc=-AOioRPsxNsAX--Y56K&tn=L4jvcTJ-sL4LoJsG&_nc_ht=scontent.fhan4-3.fna&oh=03_AVJsqxqBtiXJZVKcNhZYy_beXNgNnK0nf3GIBSS9okPgCA&oe=62A9AF53)

### ⇒ Flag:`HCMUS-CTF{c291872ada763ed9a480eca240552890}`

## 4. LostInParis - Forensics

### Thông tin ban đầu

Theo thông tin từ đề thi, chúng ta cần tìm windows-password, email-password và twitter-password và ghép lại theo structure: HCMUS-CTF{windows-password_email-password_twitter-password} để tìm ra flag.

Sau khi giải nén LostInParis.rar, ta được file forensic.

### Phân tích file forensic

Đầu tiên, dùng binwalk vào file ⇒ file forensic là 1 memory dump.

Sử dụng volatility, ta được các thông tin như sau:

```jsx
└─$ vol.py -f forensic imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
```

Từ đây, với profile là WinXPSP2x86, tiếp tục dùng volatility thu thập thông tin.

1. Cmdline
    
    Output khá vô nghĩa, ta bỏ qua những thông tin này.
    
2. Pslist
    
    ```
    0x821c8830 System                    4      0     57      265 ------      0
    0x81e9a020 smss.exe                384      4      3       19 ------      0 2013-08-29 18:59:25 UTC+0000
    0x8209e5a8 csrss.exe               568    384     11      419      0      0 2013-08-29 18:59:25 UTC+0000
    0x81b6f020 winlogon.exe            632    384     19      462      0      0 2013-08-29 18:59:27 UTC+0000
    0x81fe8020 services.exe            676    632     15      273      0      0 2013-08-29 18:59:27 UTC+0000
    0x82117970 lsass.exe               688    632     20      359      0      0 2013-08-29 18:59:27 UTC+0000
    0x81e21400 vmacthlp.exe            900    676      1       25      0      0 2013-08-29 18:59:27 UTC+0000
    0x81fe8da0 svchost.exe             916    676     20      205      0      0 2013-08-29 18:59:27 UTC+0000
    0x81df7020 svchost.exe             976    676     11      297      0      0 2013-08-29 18:59:27 UTC+0000
    0x81dd0da0 svchost.exe            1120    676     52     1144      0      0 2013-08-29 18:59:28 UTC+0000
    0x8209eb28 svchost.exe            1172    676      6       86      0      0 2013-08-29 18:59:28 UTC+0000
    0x821196d0 svchost.exe            1220    676     14      199      0      0 2013-08-29 18:59:29 UTC+0000
    0x81a6b020 spoolsv.exe            1592    676     13      142      0      0 2013-08-29 18:59:29 UTC+0000
    0x81c637e8 svchost.exe             120    676      4       84      0      0 2013-08-29 18:59:46 UTC+0000
    0x81fff638 vmtoolsd.exe            476    676      7      276      0      0 2013-08-29 18:59:46 UTC+0000
    0x81c18d68 imapi.exe              1036    676      4      118      0      0 2013-08-29 18:59:54 UTC+0000
    0x81a60020 TPAutoConnSvc.e        1140    676      5       99      0      0 2013-08-29 18:59:54 UTC+0000
    0x81a5a020 alg.exe                1300    676      6      105      0      0 2013-08-29 18:59:54 UTC+0000
    0x81b84d78 explorer.exe           2640   2612     11      340      0      0 2013-08-29 19:04:29 UTC+0000
    0x81dfe558 wscntfy.exe            2652   1120      1       35      0      0 2013-08-29 19:04:29 UTC+0000
    0x81f92650 TPAutoConnect.e        2684   1140      1       66      0      0 2013-08-29 19:04:30 UTC+0000
    0x81c09020 rundll32.exe           2928   2640      4       97      0      0 2013-08-29 19:04:42 UTC+0000
    0x81a53718 vmtoolsd.exe           2936   2640      5      207      0      0 2013-08-29 19:04:42 UTC+0000
    0x81ce17e8 ctfmon.exe             2944   2640      1       72      0      0 2013-08-29 19:04:42 UTC+0000
    0x81da1020 IncMail.exe             540   2640     21     1447      0      0 2013-08-29 19:05:03 UTC+0000
    0x820cc568 ImApp.exe              1712    916     12      381      0      0 2013-08-29 19:05:49 UTC+0000
    0x81ec0d50 wpabaln.exe            1968    632      1       66      0      0 2013-08-29 19:06:29 UTC+0000
    0x81e46668 IEXPLORE.EXE           2328    540      7      348      0      0 2013-08-29 19:06:42 UTC+0000
    0x81a19410 wordpad.exe            3212   2640      2       94      0      0 2013-08-29 19:07:58 UTC+0000
    0x81bf6020 IEXPLORE.EXE           2248   2640      6      338      0      0 2013-08-29 19:13:16 UTC+0000
    ```
    
    Ta thấy các process wordpad.exe, IncMail.exe, ImApp.exe, IEXPLORE.EXE rất đáng tìm hiểu
    
3. Clipboard
    
    ```
    0 WinSta0       0xc009L               0x901b1 0xe2482a30
    0 WinSta0       CF_UNICODETEXT       0x3803b5 0xe25bfa60 SnapshotIsReallyNiceForHacker
    0 WinSta0       0xc013L               0x901e3 0xe1cfcd78
    0 WinSta0       CF_LOCALE            0x1101ad 0xe2555818
    0 WinSta0       CF_TEXT                   0x1 ----------
    0 WinSta0       CF_OEMTEXT                0x1 ----------
    ```
    
    1 dòng data “SnapshotIsReallyNiceForHacker” rất lạ, thử lưu lại xem có gì không nào.
    
4. hashdump
    
    ```
    Administrateur:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    Invit:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    HelpAssistant:1000:860664416da453ed895ae1b92d903b5e:abfa8a32902993f56cbf8188f708ee6f:::
    SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:90caa058fbdd5bc1c14c893d571e05dd:::
    w3user:1004:5ddaeb42046e0f3f6fe90785485036fd:adfd5cfad559c822372ceb76013cc8e9:::
    ```
    

Có vẻ đã đủ, chúng ta bắt đầu với windows-password.

### 1. Windows-Password

Dựa vào hashdump, ta có thể thấy username cần quan tâm là w3user, với LM/NTLM như bên trên. [crackstation.net](http://crackstation.net) với LM hash cho ra kết quả như sau:

![Untitled](https://scontent.xx.fbcdn.net/v/t1.15752-9/277973041_538759954358126_4246364372921800582_n.png?_nc_cat=110&ccb=1-6&_nc_sid=ae9488&_nc_ohc=_sjMJNQVZXQAX-2PkbA&_nc_ht=scontent.fhan3-5.fna&oh=03_AVIYH8YoQSVqx5WSXgjrjE003pGCj56WoifU75jmdUfYww&oe=62A6F848&_nc_fr=fhan3c05)

để ý kỹ, page report yellow color, nghĩa là result chỉ gần giống so với kết quả. Thử hashing chuỗi “IL0veFobs”, kết quả thu được là chuỗi LM/Hash: “5DDAEB42046E0F3FFFFBEBD132B5C277”, không phải hash ban đầu của chúng ta.

Save hash thành file hashdump.txt, ta sẽ crack nó thủ công:

```bash
john hashdump.txt ~/Documents/rockyou.txt --format=LM
```

Sau khi run, mặc dù không đưa ra được result chính xác, nhưng output đã cho ta gợi ý như sau:

```
...
Proceeding with incremental:LM_ASCII
RENSIC			(?:2)
IL0VEFO			(?:1)
...
```

ta có thể đoán được result đại khái là “il0veforensic”, nhưng chúng ta chưa phân biệt hoa thường. Thử code 1 đoạn c++ tạo ra các tổ hợp hoa thường như sau:

```cpp
#include <iostreams>
using namespace std;
 
// Function to generate permutations
void permute(string input)
{
    int n = input.length();
 
    // Number of permutations is 2^n
    int max = 1 << n;
 
    // Converting string to lower case
        transform(input.begin(), input.end(), input.begin(),
                                                ::tolower);
    // Using all subsequences and permuting them
    for (int i = 0; i < max; i++) {
         
        // If j-th bit is set, we convert it to upper case
        string combination = input;
        for (int j = 0; j < n; j++)
            if (((i >> j) & 1) == 1)
                combination[j] = toupper(input.at(j));    
 
        // Printing current combination
        cout << combination << endl;
    }
}
 
// Driver code
int main()
{
    permute("il0veforensic");
    return 0;
}
```

build và run đoạn c++, export nó ra file passpermute.txt. 

```
il0veforensic
Il0veforensic
iL0veforensic
IL0veforensic
il0veforensic
Il0veforensic
iL0veforensic
...
```

Với dictionary là passpermute.txt, hashcat với hash NTLM:adfd5cfad559c822372ceb76013cc8e9

Input:

```bash
hashcat -m 1000 -a 0 -o cracked.txt hashdump.txt passpermute.txt
```

Output:

```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
...
```

Crack thành công, kiểm tra file cracked.txt

⇒ Windows-Password: IL0veForensic

### Twitter-Password

Theo thông tin đề bài, twitter-password được mở bởi 1 app hay 1 tiến trình nào đó đang hiển thị trên màn hình. Xem lại process list, thấy wordpad.exe là tiến trình đáng ngờ. Thử tạo memory dump cho wordpad.exe:

```
└─$ vol.py -f forensic --profile WinXPSP2x86 memdump -p 3212 -D .
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing wordpad.exe [  3212] to 3212.dmp
```

tìm các string chứa trong file dump, từ khoá là “twitter”:

```
└─$ strings 3212.dmp | grep "twitter"
\uc1\pard\f0\fs20 twitter \tab\tab w3twit:OverIsMyHero}
\uc1\pard\f0\fs20 twitter \tab\tab w3twit:OverIsMyHero}
twitter                 w3twit:OverIsMyHero
\uc1\pard\f0\fs20 twitter \tab\tab w3twit:OverIsMyHero}
\uc1\pard\f0\fs20 twitter \tab\tab w3twit:OverIsMyHero}
\uc1\pard\f0\fs20 twitter \tab\tab w3twit:OverIsMyHero}
twitter b
s20 twitter \tab\tab w3twit:OverIsMyHero}
\uc1\pard\f0\fs20 twitter \tab\tab w3twit:OverIsMyHero}
\uc1\pard\f0\fs20 twitter \tab\tab w3twit:OverIsMyHero}
```

⇒ Twitter-Password: OverIsMyHero

### Mail-Password

Vẫn theo phương pháp tìm pass twitter, kiểm tra pslist, có các tiến trình đáng ngờ như sau:

```
IncMail.exe 
ImApp.exe
```

Googling 2 tiến trình, ta có thể thấy user đang sử dụng IncrediMail Application để quản lí mail và gửi mail. Tạo memdump từ 2 tiến trình và strings “mail” nhưng không cho kết quả gì, ta sẽ chuyển hướng sang phương pháp Recovery Password. Googling Recovery password from IncrediMail, ta tìm được app IncrediMail Password Recovery đến từ Passcape.

![Untitled](https://scontent.fhan3-4.fna.fbcdn.net/v/t1.15752-9/277583692_2814902785481882_2096667798511269908_n.png?_nc_cat=104&ccb=1-6&_nc_sid=ae9488&_nc_ohc=gh09gNeFaqkAX8rtnSw&tn=L4jvcTJ-sL4LoJsG&_nc_ht=scontent.fhan3-4.fna&oh=03_AVJ-vLyJ1RBLMaFefYqO9P6U5-eIr0JrmYyL2_k7HAuSFQ&oe=62A7B462)

nó đòi hỏi file NTUSER.DAT? Trở lại file dump ban đầu, dùng công cụ volatility và listscan, từ khoá là “NTUSER.DAT”:

```
└─$ vol.py -f forensic --profile WinXPSP2x86 filescan | grep "NTUSER.DAT"
Volatility Foundation Volatility Framework 2.6.1
0x0000000002209d00      4      1 RW---- \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
0x00000000023dd6d8      1      0 R--r-- \Device\HarddiskVolume1\Documents and Settings\Default User\NTUSER.DAT
0x00000000023f2418      2      1 RW---- \Device\HarddiskVolume1\Documents and Settings\w3user\NTUSER.DAT
0x000000000250df10      4      1 RW---- \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT
```

Ta sẽ chỉ để ý đến w3user, export nó và đổi tên file thành NTUSER.DAT

```
vol.py -f forensic --profile=WinXPSP2x86 dumpfiles -Q 0x00000000023f2418 -D .
```

Thử lại với app IMPR:

![Untitled](https://scontent.fhan4-3.fna.fbcdn.net/v/t1.15752-9/278877076_410737430647960_4180687037229947638_n.png?_nc_cat=100&ccb=1-6&_nc_sid=ae9488&_nc_ohc=iX25fSmhFqcAX_lCCgW&_nc_ht=scontent.fhan4-3.fna&oh=03_AVKJCmF3zZB5xEZrnjYexDeHDyPMcVHYvmAtGkiGiw8fmA&oe=62AA9F7C)

Hmm, app chưa active, ta chỉ có thể biết được password có dạng “Sna..........”. Để ý kĩ, Sna.. trông có vẻ như Snap..., làm ta nhớ đến string mà clipboard lưu trữ: SnapshotIsReallyNiceForHacker.

Submit Flag để kiểm tra

### ⇒ FLAG: `HCMUS-CTF{IL0veForensic_SnapshotIsReallyNiceForHacker_OverIsMyHero}`