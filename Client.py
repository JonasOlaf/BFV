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

class Client():
    def __init__(self, config):
        self.context = config['context']
        self.public_key = config['public_key']

        self.encryptor = Encryptor(self.context, self.public_key)
        self.crtbuilder = PolyCRTBuilder(self.context)
        self.slot_count = (int)(self.crtbuilder.slot_count())

    def encrypt_probe(self, sample):
        features = len(sample)
        probe_matrix = [0]*self.slot_count
        for i in range(int(self.slot_count/features)):  # repeat probe n times
            for j in range(features):  # write probe
                probe_matrix[i*features+j] = sample[j]
        plain_probe = Plaintext()
        self.crtbuilder.compose(probe_matrix, plain_probe)
        encrypted_probe = Ciphertext()
        self.encryptor.encrypt(plain_probe, encrypted_probe)
        return encrypted_probe


    def enroll_db(self, references):
        templates = len(references)
        features = len(references[0])
        templates_per_cipher = int(self.slot_count/features)
        number_of_ciphers = int(templates/templates_per_cipher)

        plain_templates = [Plaintext() for i in range(number_of_ciphers)]
        encrypted_templates = [Ciphertext() for i in range(number_of_ciphers)]
        template_matrix = [[0]*self.slot_count for i in range(number_of_ciphers)]

        for i in range(number_of_ciphers):  # Each cipher
            for j in range(templates_per_cipher):  # Each subject per cipher
                for k in range(features):  # Each feature per template
                    template_matrix[i][j*features + k] = references[j+i*templates_per_cipher][k]
        for i in range(number_of_ciphers):
            self.crtbuilder.compose(template_matrix[i], plain_templates[i])
            self.encryptor.encrypt(plain_templates[i], encrypted_templates[i])

        return encrypted_templates


#
