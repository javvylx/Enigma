import os
import ember
import lightgbm as lgb

class EmberUtility:
	def __init__(self):
		self.lgbm_model = lgb.Booster(model_file=os.getcwd()+"/embermodel/ember_model_2018.txt")

	def predict_malware(self, file_path):
		# try:
		data = open(file_path, "rb").read()
		# print(dir(ember))
		return ember.predict_sample(self.lgbm_model, data, 2)
		# except:
		# 	return None

