def knn_classifier():
	import pandas as pd
	from flask import Flask, render_template, request, send_from_directory
	import numpy as np



	#训练数据
	X_train_data=pd.read_csv("classifier\knn\permissions_pickout_zero_duplicates_top20_weighted_new.csv")
	y_train_data=pd.read_csv("classifier\knn\labels.csv")
	#测试数据
	X_test_data=pd.read_csv("permissions\permissions_extract.csv")

	permissions_importances_sorted_nameAndweight_top20=pd.read_csv("classifier\knn\permissions_importances_sorted_nameAndweight_top20.csv")
	permissions_importances_sorted_name_top20=permissions_importances_sorted_nameAndweight_top20.columns.values
	permissions_importances_sorted_weight_top20=permissions_importances_sorted_nameAndweight_top20.iloc[0]

	X_test_data_top20=X_test_data[permissions_importances_sorted_name_top20]

	#print(X_test_data_top20)


	# #未加权成国公！！！！！
	# for i in range(X_test_data_top20.shape[1]):
	# 	new_value=permissions_importances_sorted_weight_top20[i] * 100
	# 	print(new_value)
	# 	X_test_data_top20.iloc[:,i].replace(1,new_value,inplace=True)

	#************有问题!!!!!!
	# i=0
	# for col in X_test_data_top20:
	# 	#print(col)
	# 	temp = permissions_importances_sorted_weight_top20[i]*100
	# 	new_col=X_test_data_top20[col].replace(1,temp)
	# 	print(new_col)
	# 	i=i+1

	#print(X_test_data_top20)

	# 构建KNN模型
	from sklearn.neighbors import KNeighborsClassifier
	knn = KNeighborsClassifier(n_neighbors=3,weights='distance')
	#训练
	knn.fit(X_train_data, y_train_data)
	results=knn.predict(X_test_data_top20)
	results=np.array([results])

	return results

