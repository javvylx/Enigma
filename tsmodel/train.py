# import tensorflow as tf
import tensorflow.compat.v1 as tf
from dataset import *

class Net(object):

	def __init__(self, x, m, c):

		self.name = 'net'
		self.inputs = x
		self.training = tf.placeholder_with_default(False, shape=None)

		with tf.variable_scope(self.name) as scope:

			self.m = tf.Variable(m, trainable=False, name='m')
			self.c = tf.Variable(c, trainable=False, name='c')

			x = m * x + c

			x = tf.layers.dense(x, 16, name='s1')
			x = tf.nn.sigmoid(x)
			
			x = tf.nn.dropout(x, tf.cond(self.training, lambda:0.5, lambda:1.0))

			x = tf.layers.dense(x, 8, name='s2')
			x = tf.nn.sigmoid(x)

			x = tf.layers.dense(x, 1, name='sf')

			self.logits = x
			self.sigmoid = tf.nn.sigmoid(x)

	@property
	def variables(self): return tf.get_collection(tf.GraphKeys.GLOBAL_VARIABLES, self.name)
	@property
	def kernels(self): return [v for v in self.variables if 'kernel' in v.name[:v.name.rfind(':')].split('/')]
	@property
	def biases(self): return [v for v in self.variables if v.name[:v.name.rfind(':')].split('/')]
	@property
	def total_params(self): return sum(reduce(lambda a,b:a*b, v.get_shape().as_list(), 1) for v in self.variables)	
	@property
	def saver(self): return tf.train.Saver(self.variables)
	@property
	def npz_saver(self): return NPZSaver(self)

if __name__ == '__main__':

	dataset = Dataset()

	P = {}
	
	batch_size = 8

	tf.compat.v1.disable_eager_execution()

	P['inputs'] =  tf.placeholder(dtype=tf.float32, shape=[batch_size, dataset.K])
	P['learning_rate'] = tf.placeholder(dtype=tf.float32)
	P['labels'] =  tf.placeholder(dtype=tf.float32, shape=[batch_size, 1])

	normalizer = MinMaxNormalizer(dataset.train.X)

	net = Net(P['inputs'], normalizer.m, normalizer.c)
	
	P['correct_prediction'] = tf.clip_by_value((P['labels'] - 0.5) * (net.sigmoid - 0.5) * 1e5, 0.0, 1.0)
	P['accuracy'] = tf.reduce_mean(P['correct_prediction'])

	with tf.control_dependencies(tf.get_collection(tf.GraphKeys.UPDATE_OPS)):
		P['nll_loss'] = tf.reduce_mean(
			tf.nn.sigmoid_cross_entropy_with_logits(logits=net.logits, labels=P['labels']))
		P['train'] = tf.train.AdamOptimizer(P['learning_rate'], epsilon=1e-8).minimize(P['nll_loss'])

	initial_learning_rate = 0.0002
	min_learning_rate = 0.000001
	learning_rate_decay_limit = 0.0001
	
	num_batches_per_epoch = 300
	learning_decay = 30 * num_batches_per_epoch
	weights_decay_after = 5 * num_batches_per_epoch

	checkpoints_dir = 'checkpoints.kn'
	if not os.path.exists(checkpoints_dir):
		os.makedirs(checkpoints_dir)

	def get_session():
		config = tf.ConfigProto(device_count={'GPU':0})
		config.gpu_options.allow_growth=True
		return tf.Session(config=config)

	with get_session() as session:

		num_batches = 2147483647
		batch_index = 0
		learning_step = 0
		session.run(tf.global_variables_initializer())

		checkpoint_num = 0

		print('Network total params: {}'.format(net.total_params))

		while batch_index < num_batches:
			
			learning_rate = max(min_learning_rate, 
				initial_learning_rate * 0.5**(learning_step / learning_decay))
			learning_step += 1

			batch_index += 1

			if batch_index and batch_index % 64 == 0:
				nll_loss = 0
				t = 10
				for d in range(t):
					inputs, labels = dataset.test.get_batch(batch_size)
					feed_dict = {
						net.training: False,
						net.inputs: inputs, 
						P['labels']: labels, 
					}			
					nll_loss += session.run(P['nll_loss'], feed_dict=feed_dict)
				nll_loss = nll_loss / float(t)
				print('nll loss: {}'.format(nll_loss))

			if batch_index and batch_index % 64 == 0:
				accuracy = 0
				t = 10
				for d in range(t):
					inputs, labels = dataset.test.get_batch(batch_size)
					feed_dict = {
						net.training: False,
						net.inputs: inputs, 
						P['labels']: labels, 
					}
					accuracy += session.run(P['accuracy'], feed_dict=feed_dict)
				accuracy = accuracy / float(t)
				print('accuracy: {}'.format(accuracy))

			inputs, labels = dataset.train.get_batch(batch_size)
			feed_dict = {
				net.training: True,
				net.inputs: inputs, 
				P['labels']: labels, 
				P['learning_rate']: learning_rate
			}
			
			session.run(P['train'], feed_dict=feed_dict)

			if batch_index and batch_index % 512 == 0:
				if checkpoint_num == 0:
					with open(checkpoints_dir+'/accuracies.txt', 'w') as f:
						f.write('')
				accuracy = 0
				t = 10
				for d in range(t):
					inputs, labels = dataset.test.get_batch(batch_size)
					feed_dict = {
						net.training: False,
						net.inputs: inputs, 
						P['labels']: labels, 
					}
					accuracy += session.run(P['accuracy'], feed_dict=feed_dict)
				accuracy = accuracy / float(t)
				print('accuracy: {}'.format(accuracy))
				print('saving checkpoint {}...'.format(checkpoint_num))
				net.npz_saver.save(session, checkpoints_dir+'/c-{}.npz'.format(checkpoint_num))
				with open(checkpoints_dir+'/accuracies.txt', 'a') as f:
					f.write(' '.join(map(str, (checkpoint_num, accuracy))) + '\n')
				print('checkpoint saved!')
				checkpoint_num += 1
