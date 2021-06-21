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

class Client():
    def __init__(self, config):
        self.context = config['context']
        self.public_key = config['public_key']

        self.features = config['features']
        self.model = None

        self.encryptor = Encryptor(self.context, self.public_key)
        self.crtbuilder = PolyCRTBuilder(self.context)
        self.slot_count = (int)(self.crtbuilder.slot_count())

    def encrypt_probe(self, sample):
        probe_matrix = [0]*self.slot_count
        for i in range(self.features):
            probe_matrix[i] = sample[i]
        plain_probe = Plaintext()
        self.crtbuilder.compose(probe_matrix, plain_probe)
        encrypted_probe = Ciphertext()
        self.encryptor.encrypt(plain_probe, encrypted_probe)
        return encrypted_probe


    def enroll_db(self, references):
        # Assume already converted to ints and lower dimension
        templates = len(references)
        features = len(references[0])  # features per cipher

        plain_templates = [Plaintext() for i in range(templates)]
        encrypted_templates  = [Ciphertext() for i in range(templates)]

        template_matrix = [[0]*self.slot_count for i in range(templates)]

        for i in range(templates):
            for j in range(features):
                template_matrix[i][j] = references[i][j]

        # for i in range(number_of_ciphers):  # loop over array of template matrices
        #     for j in range(templates_per_cipher):  # loop over the templates in each matrix
        #         if i*number_of_ciphers+j > templates:
        #             break
        #         for k in range(self.features):
        #             template_matrix[i][j*self.features + k] = references[i*number_of_ciphers+j][k]

        for i in range(templates):
            self.crtbuilder.compose(template_matrix[i], plain_templates[i])
            self.encryptor.encrypt(plain_templates[i], encrypted_templates[i])

        return encrypted_templates




#
