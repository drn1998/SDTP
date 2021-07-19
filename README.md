# SDTP
**[19.07.2021 18:41 UTC]**
I decided to make the file formats of SDTP more modular and for that reason abandon the possibility of plain-text in the commitment library and respective format. While this will mean that a release of hcommit is not possible in August due to my limited time, I think this makes more sense in the long term. There will be formats for each kind of data (plaintext message, hash commitment, access-limited hash tables etc.) and it's also possible to cascade them, e.g. a commitment containing a plaintext message or an rectangular pointer etc.

**Disclaimer and warning:** SDTP is in a very early state of development. There is no stable release and it currently does not satisfy the strict requirements for review and testing of cryptographic software.

A project that intents to implement cryptographic and steganographic concepts, especially those beyond ordinary encryption and authentication.

My first effort in that regard is the development of hcommit (hash commit) a library that creates and verifies cryptographic commitments. This will be followed by a command-line (and possibly GUI) tool to manage these, while the library can also be used in situations where it is otherwise suitable (fair random numbers, secure multiparty computation).
