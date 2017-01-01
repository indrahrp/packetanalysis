import sys
#print sys.path

class test(object):
	def __init__ (self,name):
		print "in init test nama " + name 
	def activate(self):
		print "activate"
		

def testfunc():
	#ab=test('testfuncinit')
	return test('testfuncinit')
	
	#return ab

gc=test('fd')
gc.activate ()
ab=testfunc()
ab.activate()
#test.activate()

lst=['c','a','b']
for key,value in enumerate(lst):
	print key,value
agg=sorted(lst)
#print agg
#lst.sort()
#print lst
for key,value in enumerate(lst):
	print key,value
print("\033[1;32;40m Bright Green  \n")
a="162.8.253.245.1985 > 224.0.0.2.1985: HSRPv0-hello 20: state=active group=112 addr=162.8.253.230 hellotime=3s holdtime=10s priority=120"

entries2=a.split(",")
#print isinstance(a,string)
ab='asafjdaf'
ab=5
print id(ab)
bc=ab
print id(bc)
print type(['k','l'])

def test_var_args(farg, *args):
    print "formal arg:", farg
    for arg in args:
        print "another arg:", arg

test_var_args(1, "two", 3)