def dt_classifier():
	from sklearn import tree               #导入模型
	from sklearn.model_selection import train_test_split#制作数据集和测试集
	from sklearn.model_selection  import cross_val_score
	import pandas as pd
	import numpy as np

	X_train_data=pd.read_csv("classifier\dt\permissions_pickout_zero_duplicates.csv")
	y_train_data=pd.read_csv("classifier\dt\labels.csv")

	X_test_data=pd.read_csv("permissions\permissions_extract.csv")

	from sklearn import tree
	rfc = tree.DecisionTreeClassifier(random_state=30,criterion = 'entropy',max_depth=8,min_samples_leaf=3,min_samples_split=7)
	rfc.fit(X_train_data,y_train_data)
	results=rfc.predict(X_test_data)
	results=np.array([results])

	return results


