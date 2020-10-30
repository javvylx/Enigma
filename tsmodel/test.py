import os
import sys
from .dataset import *

checkpoint_path = os.getcwd()+'/tsmodel/checkpoints.kn/c-12.npz'

class InferenceNet(object):
	
	def __init__(self, checkpoint_path):
		kwds = np.load(checkpoint_path)
		self._layers = {}
		keys = [
			'm', 'c', 
			's1/kernel', 's1/bias', 
			's2/kernel', 's2/bias', 
			'sf/kernel', 'sf/bias'
		]
		for k in keys:
			for _k in kwds:
				s = '/' + k + ':'
				if s in _k:
					self._layers[k] = kwds[_k]

		self._sigmoid = lambda x: 1.0 / (1.0 + np.exp(-x))
	
	def run(self, x):
		x = self._layers['m'] * x + self._layers['c']
		x = np.reshape(x, [-1, 1])
		x = self._sigmoid(np.matrix(self._layers['s1/kernel']).transpose() * x
			+ np.matrix(self._layers['s1/bias']).transpose())
		x = self._sigmoid(np.matrix(self._layers['s2/kernel']).transpose() * x
			+ np.matrix(self._layers['s2/bias']).transpose())
		x = self._sigmoid(np.matrix(self._layers['sf/kernel']).transpose() * x 
			+ np.matrix(self._layers['sf/bias']).transpose())
		# This is the probability that it is malign.
		# If it is > 0.5, it is malign.
		# otherwise, benign.
		x = float(x)
		return x



	def get_vectorized_row(self, f_fields):


		true_re = re.compile(r'^(t|malign)', re.IGNORECASE)
		false_re = re.compile(r'^(f|benign)', re.IGNORECASE)

		X = np.array([
			float(1 if true_re.match(str(c[1])) else (
				0 if false_re.match(str(c[1])) else c[1]
			)) for c in f_fields[1:]
		], dtype=np.float32)
		X = np.reshape(X, [1, -1])
		return X

			

		

		# for x,y in f_fields[1:]:
		# 	if 
		# print(f_fields[0])
		# for c, d in f_fields.items():
		# 	temp = str(d)

		# 	if true_re.match(dtemp):
		# 		temp = 1.0
		# 	elif false_re.match(temp):
		# 		temp = 0.0
		# 	else:
		# 		temp = float(temp)
		# 	x.append(temp)
		# x = np.array(x, dtype=np.float32)
		# X.append(x)
		# 
		sys.exit()
		# 
		return X


		# 	print(d)
		# 	# pass

		# for c in line[1:]:
		# 	if true_re.match(c):
		# 		c = 1.0
		# 	elif false_re.match(c):
		# 		c = 0.0
		# 	else:
		# 		c = float(c)
		# 	x.append(c)
		# x = np.array(x, dtype=np.float32)
		# X.append(x)







# inferenceNet = InferenceNet(checkpoint_path)

# # Let's just get a random test sample.
# dataset = Dataset()



# inputs, labels = dataset.test.get_batch(1)

# print(inferenceNet.run(inputs))
