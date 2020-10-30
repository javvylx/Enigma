import numpy as np
import csv, re, os
from functools import reduce

class Dataset(object):

	def __init__(self, file_name=os.getcwd()+'/tsmodel/dll.csv', y_name='Category'):

		labels = None
		s = 0
		self._data = {'train': [], 'test': [], 'all': []}
		self._mode = 'all'
		
		true_re = re.compile(r'^(t|malign)', re.IGNORECASE)
		false_re = re.compile(r'^(f|benign)', re.IGNORECASE)

		X = []
		with open(file_name, 'r') as f:
			reader = csv.reader(f)
			for i, line in enumerate(reader):
				if i < 1:
					labels = line[1:]
					s = labels.index(y_name)
				else:
					x = []
					for c in line[1:]:
						if true_re.match(c):
							c = 1.0
						elif false_re.match(c):
							c = 0.0
						else:
							c = float(c)
						x.append(c)
					x = np.array(x, dtype=np.float32)
					X.append(x)

		def get_random_iter(mode):
			while 1:
				order = np.arange(len(self._data[mode]['X']))
				np.random.shuffle(order)
				for i in order:
					yield i

		self._iters = {}
		
		np.random.seed(12345)
		np.random.shuffle(X)

		X = np.array(X, dtype=np.float32)
		Y = X[:,s]
		X = np.concatenate([X[:, :s], X[:, s+1:]], axis=1)

		q = int(0.8 * len(X))
		self._data['train'] = {'X': X[:q], 'Y': Y[:q]}
		self._data['test'] = {'X': X[q:], 'Y': Y[q:]}
		self._data['all'] = {'X': X, 'Y': Y}

		for k in self._data:
			self._iters[k] = iter(get_random_iter(k))
	
	@property
	def train(self):
		self._mode = 'train'
		return self

	@property
	def test(self):
		self._mode = 'test'
		return self

	@property
	def X(self):
		return self._data[self._mode]['X']

	@property
	def Y(self):
		return self._data[self._mode]['Y']

	@property
	def K(self):
		return self.X.shape[-1]

	def get_batch(self, batch_size=10):
		indices = [next(self._iters[self._mode]) for i in range(batch_size)]
		print(self.X)
		print(indices)
		print (self.X[indices])
		return self.X[indices], np.expand_dims(self.Y[indices], axis=-1)

	# def get_vectorized_row(self, dict_data):

	# 	true_re = re.compile(r'^(t|malign)', re.IGNORECASE)
	# 	false_re = re.compile(r'^(f|benign)', re.IGNORECASE)

	# 	X = []
	# 	x = []
	# 	for c in dict_data:
	# 		print(c)
	# 		# pass

	# 	for c in line[1:]:
	# 		if true_re.match(c):
	# 			c = 1.0
	# 		elif false_re.match(c):
	# 			c = 0.0
	# 		else:
	# 			c = float(c)
	# 		x.append(c)
	# 	x = np.array(x, dtype=np.float32)
	# 	X.append(x)
	# 	return 
		


class MinMaxNormalizer(object):
	
	def __init__(self, X):
		upper = np.max(X, axis=0)
		lower = np.min(X, axis=0)
		diff = upper - lower
		m = 1 / (diff + np.array(diff < 1e-5, dtype=np.float))
		self.m = m
		self.c = -lower * m

	def apply(self, Y):
		return self.m * Y + self.c	


class NPZSaver(object):
	
	def __init__(self, net):
		self._net = net
	
	def save(self, session, f):
		np.savez_compressed(f, **dict((v.name, session.run(v)) for v in self._net.variables))
	
	def restore(self, session, f):
		kwds = np.load(f)
		for v in self._net.variables:
			if v.name in kwds:
				#print v.name
				session.run(v.assign(kwds[v.name]))
