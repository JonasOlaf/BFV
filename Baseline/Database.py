import seal
from copy import deepcopy
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
import time

class Database():
    def __init__(self, config):
        #self.encrypted_templates = pickle.load(open(db_name, 'rb'))
        #self.encrypted_templates_copy = pickle.load(open(db_name, 'rb'))
        self.encrypted_templates = None
        self.features = config['features']  # number of features per cipher

        self.context = config['context']
        self.public_key = config['public_key']
        self.eval_keys = config['eval_keys']
        self.gal_keys = config['gal_keys']
        crtbuilder = PolyCRTBuilder(self.context)
        self.slot_count = (int)(crtbuilder.slot_count())
        self.evaluator = Evaluator(self.context)


		# Create [1,0,0,...,1,0,0..] matrix to multiply on identification result
        #extraction_matrix = [1 if x%self.features == 0 else 0 for x in range(self.slot_count)]
        extraction_matrix = [0]*self.slot_count
        extraction_matrix[0] = 1
        plain_extraction = Plaintext()
        self.cipher_extraction = Ciphertext()
        crtbuilder.compose(extraction_matrix, plain_extraction)
        encryptor = Encryptor(self.context, self.public_key)
        encryptor.encrypt(plain_extraction, self.cipher_extraction)

		# debugging
        self.timetest = 0
        self.timings = {'rot':0, 'arith':0}

    def set_encrypted_templates(self,  encrypted_templates):
        self.encrypted_templates = encrypted_templates

    def identify(self, probe):
        if self.encrypted_templates is None:
            print('Database not loaded.')
            return
        # make copies to preserve original, make 2nd to rotate
        templates = deepcopy(self.encrypted_templates)

        t0 = time.time()
        for template in templates:
            self.evaluator.sub(template, probe)
            self.evaluator.square(template)
            self.evaluator.relinearize(template, self.eval_keys)
        self.timings['arith'] += time.time()-t0
        templates_rot = deepcopy(templates)

		# Rotation
        t0 = time.time()
        for i in range(len(templates)):
            for j in range(self.features-1):
				# Rotate and sum
                self.evaluator.rotate_rows(templates_rot[i], 1, self.gal_keys)
                self.evaluator.add(templates[i], templates_rot[i])
        self.timings['rot'] += time.time()-t0
		# Multiply with extraction matrix

        t0 = time.time()
        for i in range(len(templates)):
            self.evaluator.multiply(templates[i], self.cipher_extraction)
            self.evaluator.relinearize(templates[i], self.eval_keys)
        self.timings['arith'] += time.time()-t0
        return templates
