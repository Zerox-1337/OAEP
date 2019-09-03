# OAEP

Using textbook RSA for encrypting messages can be very insecure for several reasons, one being that it is deterministic. 
The padding scheme OAEP can be used to solve the problem, turning RSA into a probabilistic encryption scheme. 

This is an implementation of OAEP and a direct implementation of two parts of the protocol: the MGF1 function and the ISOSP according to the RFC 8017 specification. 

