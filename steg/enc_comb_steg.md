# Combinational Steganography
This is a simple proof-of-concept tool I made in Python 3 to demonstrate the ability to hide small amounts of data (a few bytes, typically) in the order of the selection from objects.

param.ini contains two settings: i and j. i is the total number of objects that are selected from (what would be referred to as n in combinatorics) and j (or k) the selected subset.

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

Now, param.ini would have to be set like

\[combinations\]  
i = 12  
j = 5  

and enc_comb_steg.py can be invoked with any value from 0 to nPr(12,5) as a base 10 integer as cmd argument.

To transmit the value 84931, the output would be

11  
8  
10  
6  
4  

which corresponds to

wallet  
SD card  
watch  
envelopes  
CD-RW  

This is converted by interpreting the output as the n-th object to be taken from the (alphabetically ordered) stack, with elements below the taken one moving. The first value, 11, means to take the 11th element (wallet). After this step, watch becomes the 11th element, as no index can possibly be vacant. Similarly, when SD card is taken, telephone/USB drive/watch all move one position up.
