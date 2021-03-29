# Combinational Steganography
This is a simple proof-of-concept tool I made in Python 3 to demonstrate the ability to hide small amounts of data (a few bit to bytes, typically) in the order of the selection from objects.

`param.ini` contains a single setting: j. It is the number of objects that are selected from the list given as input. j can also be set to -1 to automatically set it to the total number of elements in the list. This generated a full permutation, not just selecting a subset from the list.

For example, if Alice and Bob have agreed on a list of 12 objects she has in the room where she works:

9V battery  
AA batteries  
camera  
CD-RW  
charger  
envelopes  
pencil  
SD card  
telephone  
USB drive  
wallet  
watch  

and will send a picture of the desk to Bob (or publish it, say, on social media) containing 5 of those 12 objects, any number from 0 to nPr(12,5) can be hidden steganographically inside the unsuspicious photo. This requires that the objects have a well-defined, controllable order, which might be the clockwise appearance in the photo.

Now, `param.ini` would have to be set like

\[combinations\]  
j = 5  

and `enc_comb_steg.py` can be invoked with a list of elements as text file and any value from 0 to nPr(12,5) as a base 10 integer as cmd argument. The maximum size in bit of the data can be calculated with `python3 enc_comb_steg.py elem.csv -r`:

16 bit

To transmit the value 84931, the command is `python3 enc_comb_steg.py elem 84931` which returns:

wallet  
SD card  
watch  
envelopes  
CD-RW  

## Limitations
- Alice and Bob have to define an agreed order of the objects. Alphabetical ordering is usually reasonable and should be chosen unless there are compelling reasons against it.
- The list must not contain objects multiple times. The script currently cannot automatically recognize violations of this rule.
- If the input number is always binary, some values (and therefore combinations) can never be reached which is a stochastic entrypoint for steganalysis. Countermeasures like adding a bias that can be unambiguously subtracted when decoding are not implemented so far.
