# Combinational Steganography
This is a simple proof-of-concept tool I made in Python 3 to demonstrate the ability to hide small amounts of data (a few bit to bytes, typically) in the order of the selection from objects.

`param.ini` contains a single setting: j. It is the number of objects that are selected from the list given as input.

For example, if Alice and Bob have agreed on a list of 12 objects she has in the room where she works:

9V batteries  
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

and `enc_comb_steg.py` can be invoked with a list of elements as text file and any value from 0 to nPr(12,5) as a base 10 integer as cmd argument. The range of valid integers can be calculated with `python3 enc_comb_steg.py elem.csv -r`:

0 - 95039, 16 bit

To transmit the value 84931, the command is `python3 enc_comb_steg.py elem.csv 84931` which returns:

wallet  
SD card  
watch  
envelopes  
CD-RW  
