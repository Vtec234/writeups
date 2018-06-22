# ECSC 18 Polish Junior Quals: keybd.py

All we get in this challenge is a file, [`keybd.pcapng`](https://hack.cert.pl/files/keybd-e724c1d71f535ed2fc401779b4e6c171b506c0a7.pcapng). This is a packet dump, so let's look at it in Wireshark.
On a first glance, we can see that it's a capture of the USB protocol. The first two packets reveal that the recorded communications are between the computer and a USB keyboard:
![assets/wire1.png]

After the initial descriptor transfer, we have a bunch of `URB_INTERRUPT` type transfers. Presumably, these contain the keypresses, but to decode them manually would require understanding
the USB HID (Human Interface Device) protocol, which seems like a lot of work. At this point, I got the idea of simply replaying the keypresses in a VM and looking at the output, so I fired
up a VM with a keyboard device and ran [this tool](https://bitbucket.org/dwaley/usb-reverse-engineering). That didn't work so well (or at all), so I took to searching some more and found
[this lovely website](https://bitvijays.github.io/LFC-Forensics.html) which details how to extract what Wireshark calls "capture data", which contains the currently pressed keys in the following format:
`[modifier, reserved, Key1, Key2, Key3, Key4, Key6, Key7]`. Using the keycode map [here](https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2) and some Python code to remove
duplication of keys which were pressed for more than one interrupt, we can turn the keypresses into a readable stream:
```
SUDO<SPACE>PYTHON<SPACE>KEY<DOT>B<BACKSPACE>BD<DOT>PY<ENTER>HACKERTYPER<DOT>COM<ENTER>DJJSKISKDASJDODJIOEJFIOEJWEPOFJWFWJOWEWOPFWE<LEFTBRACE>TOER<RIGHTBRACE><LEFTBRACE>Y<LEFTBRACE><RIGHTBRACE>TYHY<RIGHTBRACE><LEFTBRACE>JGL<LEFTBRACE>FKROGWEIFEWOUIFHEUIFHWEOFJWEIFWEFJEPFOWEKFPWEKFOPWEJFWIOFHEUIFHWIUEFJWEOPFJKWEOPFJWEIFHWEOFWPFJWEOIFWEJFJWEFIOEJWFOPJFIEO<SEMICOLON>FWEHF<SEMICOLON>FJKSDKLVSDL<SEMICOLON>VDFB<SEMICOLON>JVJSFHSLFSFDGPRKHPHUIOEHFUIWEGFWEYVGFWEFDKBDFNBLFBJOJDFIOGHSFUIGFSDFHSDFJSDGFJKDFOGHSDFUSGHFISGDFYUSDGFSDJKHSDKVHJSDL<SEMICOLON>VHJSDIOVGHSFYUGWEFEHFOJGEROPGJPEROFJWPDFHAUISGFUIASGDAYSGFSIDFHDFOGJFPHKGFPKGFPNKGFOPBJDUISHFSUGFSYUDASYUDGAUIFHSDOJDFBOKFBPFKPGFJKIODHSDFIASGDYDAYUDVAYUDGSDUIFHSOGJDFOGOPBKONPDFJGOJIUSFUISGFYUSDVGIAUDFHAOSDFHJOFIJFPBGDFJKBPDFNJVIOSDHFUIASFASUIFAUIBFAOFASOFNAFIOASFENFIHF8O73892934957430574309573490574905735097489329482Y4234I23H4OI23HO23HO23H4O32HO3H2OI23HIOHYWE89FHC98SHOSEHF89EHV9SEHVS9VYSD89VSD98VYSDYVS89VHSDVHEOFHYS9OFHSOEFY8OEVFISSIVOSDHVSDIOVHSDVGSDUIDHOGODFBOJBODJVISGVSUIGCSIDCVIOVHDOJVODFBDIOFNDIFOHVSUIVGSODVHSDIOVHSDIOVGSCIUDHBDFOHPDUIOGFAOCHJSDPCJKASPCJSAPCJSOPCJSOPAJCP9FEPJUSDPVJPSDVUSD9VUSDPVSDVPOJVPODUV9SPDVUJDPSVJSDPOVJUSD9PVUSDPVJDVJSDPVOJDSP9VUDS9PVSDPVJEPVERJ9EPF7UE0W9RU2PORJPRJPEWFUWE99OFYDV7TSD78VGSOVHGOPJGNPKNPHGKNGPJFVHSDGUGCYUFYUYUAFCUAGCDSGHVIHBOJBOGJNNPFNKHPMPJNIHUIVIGSYUSYUASYUASYUWEUIEW8WE98WE89WE89WE898WE89WE893247823723834905I45KI34ME4IKDJSISOISUSYUAUOSOEIWUEIRUEIWUEIWUE73838383838383KDKDKDKDKDKDIEIEIEIEIEIEI83E8EIOWJIOFWEHFUIASGIDASHIODFOGFHJIOGFJHFISDFUSDFHISDUUIUSDUIDIUDISIUDUISUDUDUSIDUDUDUDUDSIOFOPGPOGFISUSSDFJKLHJDFJKSDFHKGDGHLGFJKG<SEMICOLON>HJDIGOHSFUISHFSDUIFSDFJDSPFOSJFOPSDDF<EQUAL>SD<MINUS>FSD<EQUAL>F<MINUS><EQUAL>S<EQUAL><MINUS>1231231231231231453547687904DFKFKFKDKSDKSKSKSKWIEIEIROROTOTPYPQWERTYUIOPOIUYTREWQASDFGHJKLKJHGFDSAQQWWQWEW

```
Unfortunately there is no flag in here :( There is an especially annoying stream of keys, which I thought looked less random than the rest and spent a good few hours trying to decode:
`8O73892934957430574309573490574905735097489329482`

Having given up on that, I looked again at the key stream and realised that the command executed at the beginning, `sudo python keybd.py` cannot be the keylogger itself, because typing
it in is already being logged. So, it must be something else. Back to Wireshark:
![assets/wire2.png]

Lo and behold, right after the command starts, we see a different kind of USB transfer begin, using `URB_CONTROL` packets. What's more, these packets contain a different last byte
every time:
![assets/wire3.png]

Let's look at these and see if they contain anything interesting. I dumped the `URB_CONTROL` packet contents into a plaintext file and then extracted the last bytes using some Vim macros.
The LSB in them is simply alternating between `0` and `1`, so it cannot be text and should be discarded. However, the 2nd LSB (`0b000000X0`) changes in a non-trivial way. What's more,
there are exactly 241 of these packets, which is almost exactly 30 bytes. Cutting the first bit off to make it even and decoding the values as a bitstream, I got the flag :D
