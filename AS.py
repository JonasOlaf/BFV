import seal
from seal import ChooserEvaluator, \
	Ciphertext, \
	Decryptor, \
	Encryptor, \
	EncryptionParameters, \
	Evaluator, \
	IntegerEncoder, \
	FractionalEncoder, \
	KeyGenerator, \
	MemoryPoolHandle, \
	Plaintext, \
	SEALContext, \
	EvaluationKeys, \
	GaloisKeys, \
	PolyCRTBuilder, \
	ChooserEncoder, \
	ChooserEvaluator, \
	ChooserPoly
from math import ceil
import pdb
import time

class AuthenticationServer():
    def __init__(self, features, slots):
        # Initialise system
        parms = EncryptionParameters()
        parms.set_poly_modulus(f"1x^{slots} + 1")
        parms.set_coeff_modulus(seal.coeff_modulus_128(slots))
        parms.set_plain_modulus(40961)
        self.context = SEALContext(parms)
        self.crtbuilder = PolyCRTBuilder(self.context)

        # Generate keys
        keygen = KeyGenerator(self.context)
        self.public_key = keygen.public_key()
        self.secret_key = keygen.secret_key()
        self.decryptor = Decryptor(self.context, self.secret_key)
        self.gal_keys = GaloisKeys()
        keygen.generate_galois_keys(30, self.gal_keys)
        self.eval_keys = EvaluationKeys()
        keygen.generate_evaluation_keys(30, self.eval_keys)

        self.features = features  # size of embedding
        self.templates = None
        self.slot_count = (int)(self.crtbuilder.slot_count())

        self.last_dists = None  # debugging
        self.timings = {'dec':0}


    def setup_database(self):
        config = {}
        config['public_key'] = self.public_key
        config['eval_keys'] = self.eval_keys
        config['gal_keys'] = self.gal_keys
        config['context'] = self.context
        config['features'] = self.features

        return config

    def setup_client(self):
        config = {}
        config['context'] = self.context
        config['public_key'] = self.public_key

        return config

    def decrypt(self, enc_dists):  # Takes in encrypted database, returns list of distances
        t0 = time.time()
        plains = [Plaintext() for i in range(len(enc_dists))]
        dists = []
        for i in range(len(enc_dists)):
            self.decryptor.decrypt(enc_dists[i], plains[i])
            self.crtbuilder.decompose(plains[i])
            dists.append([plains[i].coeff_at(j) for j in range(plains[i].coeff_count())])
        self.timings['dec'] += time.time()-t0
        return dists


    def get_identity(self, dists):
		# Given dists matrix from decrypt, return identity and distance as tupple
        d = []
        templates_per_cipher = int(self.slot_count/self.features)
        number_of_ciphers = ceil(self.templates/templates_per_cipher)

        for i in range(number_of_ciphers):
            for j in range(templates_per_cipher):
                d.append(dists[i][j*self.features])
        ID = d.index(min(d))

        return (ID, d[ID])



if __name__ == '__main__':
    AS = AuthenticationServer(features=96)
