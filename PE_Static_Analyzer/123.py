import os
import ember
# print (ember.__path__)
import lightgbm as lgb



model_path = "C:\\Users\\User\\Desktop\\ember_related\\ember_dataset_2018_2\\ember2018\\ember_model_2018.txt"
	
lgbm_model = lgb.Booster(model_file=model_path)

test_data = open("C:\\Users\\User\\Desktop\\123456.exe", 'rb').read()
# print(test_data)
# print(dir(ember))
# print(ember.pd(test_data))


# kps = "C:\\Users\\user\\Desktop\\showkevin.csv"
kp = "C:\\Users\\User\\Desktop\\27-10-2020_20-52-14_test\\exesample\\"

for f in os.listdir(kp):
	test_buf = open(kp+f, 'rb').read()
	print(ember.predict_sample(lgbm_model, test_buf))

# data_path = 'C:\\Users\\User\\Desktop\\New folder (2)\\ember_dataset_2018_2\\ember2018'
# ember.create_vectorized_features(data_path)
# ember.create_metadata(data_path)