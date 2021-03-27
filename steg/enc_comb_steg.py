import sys
import math
from configparser import ConfigParser

def nPr(n, r):
	return math.factorial(n)//math.factorial(n-r)

config = ConfigParser()
config.read('param.ini')

i = config.getint('combination', 'i')
j = config.getint('combination', 'j')

if len(sys.argv) != 2:
	print("Invalid argument")
	quit()

valueToSteg = int(sys.argv[1])

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
	pos = (valueToSteg // div) + 1
	valueToSteg = valueToSteg % div
	print(pos)
