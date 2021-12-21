import datetime
import random
import gmpy2
from gmpy2 import *
import time


def get_time(mnt_inc, sec_inc):
	time= datetime.datetime.now()
	dt= str(time.day)
	mn= str(time.month)
	yr= str(time.year)
	hr= int(time.hour)
	mnt= int(time.minute+mnt_inc)
	sec= int(time.second+sec_inc)
	mnt= mnt+sec//60
	hr= str(hr+mnt//60)
	mnt= str(mnt%60)
	sec= str(sec%60)
	if(len(mn)<2):
		mn= '0'+mn
	if(len(dt)<2):
		dt= '0'+dt
	# if(len(hr)<2):
	# 	hr= '0'+hr
	if(len(mnt)<2):
		mnt= '0'+mnt
	if(len(sec)<2):
		sec= '0'+sec
	time= ''
	time= hr+mnt+sec #+' '+dt+'-'+mn+'-'+yr
	return time


class RSA:

	e= -1
	d= -1
	listType= [] # For detecting whether the character at that position is an alphabet or a digit
	listValues= [] # For detecting whether that character value is in single digit or double for eg. if 'a'=1 than 'j'=10 we have to decode in that way

	def __init__(self, p, q):
		self.p= p
		self.q= q
		self.phi= (p-1)*(q-1)
		self.n= p*q
		self.listType= []
		self.listValues= []

	
	def isPrime(self, val):
		if(val== 1):
			return False
		i= 2;
		while(i*i <= val):
			if(val%i== 0):
				return False
			i+=1;
		return True


	def calc_e(self):
		while(True):
			num= random.randint(self.q+1, self.phi-1)
			if(self.isPrime(num)):
				return num
		return 2


	def euclid(self, e, phi, q_list, r_list):
		if(e== 0):
			return q_list, r_list, self.phi
		q_list.append(phi//e)
		r_list.append(phi%e)
		return self.euclid(phi%e, e, q_list, r_list) 


	def calc_values(self):
		q_list= [0,0]
		r_list= [0,0]
		self.e= self.calc_e()
		return self.euclid(self.e, self.phi, q_list, r_list)


	def calc_d(self):
		d_list= [0,1]
		q_list, r_list, phi= self.calc_values()
		for i in range(2, len(q_list)):
			d_list.append(d_list[i-2]-q_list[i] * d_list[i-1])
		return mpz(self.e), mpz(d_list[len(d_list)-2]), mpz(self.n), mpz(self.phi)


	def generate_keys(self):
		while(True):
			e,d,n,phi= self.calc_d()
			if(d>0):
				break;
		return e,d,n,phi


	def generate_cipher_text(self, msg, e, n):
		self.listType= []
		self.listValues= []
		e= mpz(e)
		n= mpz(n)
		msgConv= ''
		# print("MSG Before CONV.", msg)
		for i in msg:
			asci= ord(i)
			if(i.isalpha()):
				if(i.isupper()):
					self.listType.append('u')
					val= asci-65
				else:
					self.listType.append('l')
					val= asci-97
			elif(i.isdigit()):
				self.listType.append('d')
				val= asci-48
			else:
				self.listType.append('o')
				val= asci
			msgConv= msgConv+str(val)
			count= 0
			if(val== 0):
				self.listValues.append(1)
			else:
				while(val>0):
					count= count+1
					val= val//10
				self.listValues.append(count)
		msg= mpz(int(msgConv))
		# print("C_MSG IN DIG", msg)
		return mpz(powmod(msg, e, n))


	def decipher_ciphered_text(self, cipher_text, d, n, listType, listValues):
		self.listType= list(listType)
		self.listValues= list(listValues)
		cipher_text= mpz(cipher_text)
		val= str(mpz(powmod(cipher_text, d, n)))
		# while(len(val)<6):
		# 	val='0'+val
		# print("Msg after Decryption:", val)
		msg= ''
		# print(self.listValues)
		for i in range(0, len(self.listValues)):
			end= self.listValues[i]
			valType= self.listType[i]
			slicing= int(val[0:end])
			val= val[end:len(val)]
			if(valType== 'u'):
				slicing= slicing+65
			elif(valType== 'l'):
				slicing= slicing+97
			elif(valType== 'd'):
				slicing= slicing+48
			else:
				slicing= slicing
			msg= msg+ str(chr(slicing))
		# print("MSG", msg)
		return msg



class PublicKeyAuth:

	__public_keys= {}
	__update_public_keys= {}
	__valid_time= {}
	__time_extension= 10
	__RSAobj= RSA(1003787, 1315367)
	__values= __RSAobj.generate_keys()
	__private_key= __values[1]
	__public_key= __values[0]
	__n= __values[2]
	__listType= {} # It will be nested cause a connection can have several incoming connections. 
	__listValues= {} # It will be nested cause a connection can have several incoming connections.
	__listType1= {}
	__listValues1= {}
	__nValue= {}

	def get_public_key(self):
		return self.__public_key, self.__n


	def get_type_values(self, id1, id2):
		return self.__listType[id1][id2], self.__listValues[id1][id2], self.__listType1[id1][id2], self.__listValues1[id1][id2]


	def get_n_value(self, id):
		return self.__nValue[id]


	def request_public_key(self, id1, id2):
		extracted_time= ''
		if(id2 in self.__public_keys):
			time= get_time(0, self.__time_extension)
			extracted_time= time
			self.__valid_time[id1]= {id2: extracted_time}
			id= str(self.__public_keys.get(id2))
			msg1= str(self.__RSAobj.generate_cipher_text(id, self.__private_key, self.__n))

			self.__listType[id1]={id2: tuple(self.__RSAobj.listType)}
			self.__listValues[id1]={id2: tuple(self.__RSAobj.listValues)}

			msg2= str(self.__RSAobj.generate_cipher_text(extracted_time, self.__private_key, self.__n))

			self.__listType1[id1]={id2: tuple(self.__RSAobj.listType)}
			self.__listValues1[id1]={id2: tuple(self.__RSAobj.listValues)}


			length= len(msg2)
			temp= length
			digits= 0
			while(length>0):
				digits= digits+1
				length= length//10
			length= str(temp)
			msg= msg1 + msg2 + length + str(digits)
			print("Encrypted message send by PKA to the requesting client:", msg)
			return True, msg
		else:
			return False, 'Invalid ID'


	def update_key(self, pswd, id, public_key):
		if pswd in self.__update_public_keys:
			self.__update_public_keys[pswd]= {id: public_key}
			self.__public_keys[id]= public_key


	def add_key(self, pswd, id, public_key, n):
		if id not in self.__public_keys:
			self.__public_keys[id]= public_key
			self.__nValue[id]= n
			self.__update_public_keys[pswd]= {id: public_key}
			print("Public Keys with PKA:", self.__public_keys)


class Clients:
	
	__id= -1
	__pswd= ''
	__public_key= -1
	__private_key= -1
	__established_connections= {} # maintaining records of the id's to which it is connected with its respective valid time
	__connections_key= {}
	__KeyAuth= ''
	__RSAobj= ''
	__nonce= 0
	__n= 0
	__listType= {} # This will not be nested
	__listValues= {} # Will not be nested
	

	def __init__(self, id, p, q, pswd):
		self.__id= id
		self.__pswd= pswd
		self.__KeyAuth = PublicKeyAuth()
		self.__initialize(p, q)
		self.add_key()


	def __initialize(self, p, q):
		self.__RSAobj = RSA(p, q)
		values= self.__RSAobj.generate_keys()
		self.__public_key= values[0]
		self.__private_key= values[1]
		self.__n= values[2]


	def add_key(self):
		self.__KeyAuth.add_key(self.__pswd, self.__id, self.__public_key, self.__n)


	def update_key(self, public_key):
		self.__KeyAuth.update_key(self.__pswd, self.__id, public_key)


	def find_time(self):
		pass


	def initiate(self, id):
		public_key= ''
		check= True # If connection is already established then check will be true

		if(id not in self.__established_connections or self.__established_connections[id] <= get_time(0,0)):
			print("ID:", self.__id,"is requesting for the public key of ID:",id)
			values= self.__KeyAuth.request_public_key(self.__id, id)	
			check= values[0]
			values= values[1]
			l_dig= int(values[len(values)-1])
			values= values[0:len(values)-1] # Removes last digit

			time_length= int(values[len(values)-l_dig:])
			values= values[0:len(values)-l_dig] # Removes the last l_dig digits

			msg= values[0:len(values)-time_length]
			time_value= values[len(values)-time_length:] 

			type_values= self.__KeyAuth.get_type_values(self.__id, id)
			self.__listType[id]= type_values[0]
			self.__listValues[id]= type_values[1]

			val= self.__KeyAuth.get_public_key()
			time_decipher= str(self.__RSAobj.decipher_ciphered_text(time_value, val[0], val[1], type_values[2], type_values[3]))
			self.__established_connections[id]= time_decipher

			public_key= str(self.__RSAobj.decipher_ciphered_text(msg, val[0], val[1], type_values[0], type_values[1]))
			self.__connections_key[id]= public_key

		else:
			public_key= self.__connections_key[id]


		if(check):
			return True, public_key

		return False, 'Invalid'


	def send_message(self, id, mode, text, listType, listValue):
		if(mode== 's'):
			print("MESSAGE SENT BY id:", self.__id, "to id:", id)
			data= self.initiate(id)
			if(data[0]):
				# print(self.__id)
				self.__nonce= self.__nonce+1

				# data[1] contains the public key of 'B', encrypt the msg using data[1], 'B' will decipher it using its private key
				print("PUBLIC KEY of the client to whom message will be sent:", data[1])
				msg= 'Hi'+str(self.__nonce)
				msg= self.__RSAobj.generate_cipher_text(msg, data[1], self.__KeyAuth.get_n_value(id))
				self.__listType[id]= self.__RSAobj.listType
				self.__listValues[id]= self.__RSAobj.listValues
				dict_clients[id].respond(self.__id, msg, self.__listType[id], self.__listValues[id])
		else:
			msg= self.__RSAobj.decipher_ciphered_text(text, self.__private_key, self.__n, listType, listValue)
			print("DECRYPTED MeSSAGE:", msg)


	def respond(self, id, text, listType, listValue):
		# print("Details:2, ", id, text, listType, listValue)
		data= self.initiate(id)
		if(data[0]):
			# print(self.__id)
			print("PUBLIC KEY of the client to whom message will be sent", data[1])
			self.__nonce= self.__nonce+1
			msg= self.__RSAobj.decipher_ciphered_text(text, self.__private_key, self.__n, listType, listValue)
			print("DECRYPTED MeSSAGE:", msg)
			msg= 'Got-it'+str(self.__nonce)
			msg= self.__RSAobj.generate_cipher_text(msg, data[1], self.__KeyAuth.get_n_value(id))
			self.__listType[id]= self.__RSAobj.listType
			self.__listValues[id]= self.__RSAobj.listValues
			dict_clients[id].send_message(self.__id, 'r', msg, self.__listType[id], self.__listValues[id])


dict_clients= {}
A = Clients(1, 1003787, 1315367, 'A')
B = Clients(2, 1003787, 1315367, 'B')
dict_clients[1]= A
dict_clients[2]= B


# 10 seconds time extension is given so a connection once established is valid for 10 seconds after that it will request public key again
A.send_message(2,'s',0,[],[])
time.sleep(10)
print()
B.send_message(1,'s',0,[],[])
time.sleep(10) # At this point 10 seconds gets over and therefore it will again request for the public keys
print()
A.send_message(2,'s',0,[],[]) 