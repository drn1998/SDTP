import sys
import math
import csv
from configparser import ConfigParser

def nPr(n, r):
	if(n == r):
		return math.factorial(n)
	else:
		return math.factorial(n)//math.factorial(n-r)

config = ConfigParser()
config.read('param.ini')

if len(sys.argv) != 3:
	print("Invalid argument")
	quit()

fd = open(sys.argv[1], 'r')
elem = fd.read().split('\n')
fd.close()

elem.pop() #Remove single empty element at the end

i = len(elem)
j = config.getint('combination', 'j')

if j == -1:
	j = i

if sys.argv[2] == "-r":
	print(str(math.floor(math.log2(nPr(i, j)))) + " bit")
	quit()

valueToSteg = int(sys.argv[2])

if valueToSteg >= nPr(i, j):
	print("Out of range")
	quit()

if j > i:
	print("Invalid val for j")
	quit()

while j > 0:
	j -= 1
	i -= 1
	div = nPr(i, j) #Almost cuts runtime in half
	pos = valueToSteg // div
	valueToSteg = valueToSteg % div
	print(elem.pop(pos))

quit()
